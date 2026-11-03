// Package interop runs EDHOC sessions between this package and other
// implementations.
//
// Each implementation has a peer program that runs one side of a session,
// reading and writing messages as hex lines on stdin and stdout. After the
// handshake it prints the OSCORE master secret and salt, then the master secret
// after a key update. A test is skipped unless its environment variable points
// at the peer:
//
//	LAKERS_PYTHON    a Python with lakers-python installed
//	UOSCORE_PEER     the binary built by uoscore/build.sh
//	LIBEDHOC_PEER    the binary built by libedhoc/build.sh
package interop

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/aquilliam/edhoc"
)

// The keys and credentials every peer uses: those of RFC 9529, Section 3, with
// CRED_I shortened as in the lakers-python tests.
var (
	credI = unhex("A202617808A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8")
	skI   = unhex("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b")
	skR   = unhex("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac")
	credR = unhex("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072")
	ctx   = unhex("a01158fdb820890cd6be169602b8bcea")
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// A session describes one run: which side Go takes and how each side sends
// its credential, "reference" (by kid) or "value" (in kccs).
type session struct {
	goInitiates        bool
	goSends, peerSends string
}

func (s session) name() string {
	role := "go responder"
	if s.goInitiates {
		role = "go initiator"
	}
	return fmt.Sprintf("%s, go by %s, peer by %s", role, s.goSends, s.peerSends)
}

// sessions returns every combination of roles and of the given ways for Go and
// the peer to send their credentials.
func sessions(goSends, peerSends []string) []session {
	var out []session
	for _, goInitiates := range []bool{true, false} {
		for _, g := range goSends {
			for _, p := range peerSends {
				out = append(out, session{goInitiates, g, p})
			}
		}
	}
	return out
}

var both = []string{"reference", "value"}

func TestLakers(t *testing.T) {
	python := os.Getenv("LAKERS_PYTHON")
	if python == "" {
		t.Skip("set LAKERS_PYTHON to a Python with lakers-python installed")
	}
	for _, s := range sessions(both, both) {
		t.Run(s.name(), func(t *testing.T) {
			run(t, []string{python, "-I", "lakers/peer.py"}, s)
		})
	}
}

func TestUoscore(t *testing.T) {
	bin := os.Getenv("UOSCORE_PEER")
	if bin == "" {
		t.Skip("set UOSCORE_PEER to the binary built by uoscore/build.sh")
	}
	// uoscore does not support credentials in kccs.
	ref := []string{"reference"}
	for _, s := range sessions(ref, ref) {
		t.Run(s.name(), func(t *testing.T) {
			run(t, []string{bin}, s)
		})
	}
}

func TestLibedhoc(t *testing.T) {
	bin := os.Getenv("LIBEDHOC_PEER")
	if bin == "" {
		t.Skip("set LIBEDHOC_PEER to the binary built by libedhoc/build.sh")
	}
	// libedhoc does not support credentials in kccs.
	ref := []string{"reference"}
	for _, s := range sessions(ref, ref) {
		t.Run(s.name(), func(t *testing.T) {
			run(t, []string{bin}, s)
		})
	}
}

// peer is a process on the other side of a session.
type peer struct {
	t   *testing.T
	in  io.WriteCloser
	out *bufio.Scanner
}

func startPeer(t *testing.T, argv []string, role, transfer string) *peer {
	cmd := exec.Command(argv[0], append(argv[1:], role, transfer)...)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		in.Close()
		cmd.Wait()
	})
	return &peer{t: t, in: in, out: bufio.NewScanner(out)}
}

func (p *peer) send(b []byte) {
	if _, err := fmt.Fprintf(p.in, "%x\n", b); err != nil {
		p.t.Fatal(err)
	}
}

func (p *peer) recv() []byte {
	if !p.out.Scan() {
		p.t.Fatalf("peer exited early: %v", p.out.Err())
	}
	b, err := hex.DecodeString(strings.TrimSpace(p.out.Text()))
	if err != nil {
		p.t.Fatal(err)
	}
	return b
}

func credential(t *testing.T, raw []byte, byValue bool) edhoc.Credential {
	c, err := edhoc.ParseCCS(raw)
	if err != nil {
		t.Fatal(err)
	}
	if byValue {
		c.ID = edhoc.KCCS(raw)
	}
	return c
}

// lookup accepts the peer's credential by kid or by value, as long as it is
// the expected one.
func lookup(want edhoc.Credential) func(context.Context, *edhoc.PeerInfo) (edhoc.Credential, error) {
	return func(_ context.Context, p *edhoc.PeerInfo) (edhoc.Credential, error) {
		if ccs, ok := p.ID.KCCS(); ok && bytes.Equal(ccs, want.Raw) {
			return want, nil
		}
		if kid, ok := p.ID.KeyID(); ok {
			if wantKID, _ := want.ID.KeyID(); bytes.Equal(kid, wantKID) {
				return want, nil
			}
		}
		return edhoc.Credential{}, edhoc.ErrUnknownCredential
	}
}

// run runs one session with method 3 and cipher suite 2 against the peer and
// checks that both sides export the same keys.
func run(t *testing.T, argv []string, s session) {
	goByValue := s.goSends == "value"
	own, peerCred, sk := credential(t, credI, goByValue), credential(t, credR, false), skI
	role := "responder"
	if !s.goInitiates {
		own, peerCred, sk = credential(t, credR, goByValue), credential(t, credI, false), skR
		role = "initiator"
	}
	key, err := ecdh.P256().NewPrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &edhoc.Config{
		Method:         edhoc.MethodStaticStatic,
		Suites:         []edhoc.Suite{edhoc.Suite2},
		Credential:     own,
		Key:            key,
		PeerCredential: lookup(peerCred),
	}
	p := startPeer(t, argv, role, s.peerSends)

	var sess *edhoc.Session
	if s.goInitiates {
		i, err := edhoc.NewInitiator(cfg, []byte{0x05})
		if err != nil {
			t.Fatal(err)
		}
		msg1, err := i.WriteMessage1()
		if err != nil {
			t.Fatal(err)
		}
		p.send(msg1)
		if _, err := i.ReadMessage2(t.Context(), p.recv()); err != nil {
			t.Fatal(err)
		}
		msg3, err := i.WriteMessage3()
		if err != nil {
			t.Fatal(err)
		}
		p.send(msg3)
		if _, err := i.ReadMessage4(p.recv()); err != nil {
			t.Fatal(err)
		}
		sess, err = i.Session()
		if err != nil {
			t.Fatal(err)
		}
	} else {
		r, err := edhoc.NewResponder(cfg)
		if err != nil {
			t.Fatal(err)
		}
		m1, err := r.ReadMessage1(t.Context(), p.recv())
		if err != nil {
			t.Fatal(err)
		}
		cR := []byte{0x05}
		if bytes.Equal(cR, m1.PeerConnID) {
			cR = []byte{0x06}
		}
		msg2, err := r.WriteMessage2(cR)
		if err != nil {
			t.Fatal(err)
		}
		p.send(msg2)
		if _, err := r.ReadMessage3(t.Context(), p.recv()); err != nil {
			t.Fatal(err)
		}
		msg4, err := r.WriteMessage4()
		if err != nil {
			t.Fatal(err)
		}
		p.send(msg4)
		sess, err = r.Session()
		if err != nil {
			t.Fatal(err)
		}
	}

	compare := func(name string, label, length int) {
		t.Helper()
		got := p.recv()
		want, err := sess.Exporter(label, nil, length)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: peer %x, Go %x", name, got, want)
		}
	}
	compare("OSCORE master secret", 0, 16)
	compare("OSCORE master salt", 1, 8)
	if err := sess.KeyUpdate(ctx); err != nil {
		t.Fatal(err)
	}
	compare("master secret after key update", 0, 16)
}
