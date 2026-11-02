// Package interop runs EDHOC sessions between this package and other
// implementations.
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

// The values in peer.py.
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

// peer is a lakers process on the other side of a session.
type peer struct {
	t   *testing.T
	in  io.WriteCloser
	out *bufio.Scanner
}

func startPeer(t *testing.T, python, role, transfer string) *peer {
	cmd := exec.Command(python, "-I", "peer.py", role, transfer)
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
		p.t.Fatalf("lakers exited early: %v", p.out.Err())
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

func TestLakers(t *testing.T) {
	python := os.Getenv("LAKERS_PYTHON")
	if python == "" {
		t.Skip("set LAKERS_PYTHON to a Python with lakers-python installed")
	}
	for _, goInitiates := range []bool{true, false} {
		for _, transfer := range []string{"reference", "value"} {
			name := fmt.Sprintf("go responder, %s", transfer)
			if goInitiates {
				name = fmt.Sprintf("go initiator, %s", transfer)
			}
			t.Run(name, func(t *testing.T) {
				testLakers(t, python, goInitiates, transfer)
			})
		}
	}
}

func testLakers(t *testing.T, python string, goInitiates bool, transfer string) {
	byValue := transfer == "value"
	own, peerCred, sk := credential(t, credI, byValue), credential(t, credR, false), skI
	role := "responder"
	if !goInitiates {
		own, peerCred, sk = credential(t, credR, byValue), credential(t, credI, false), skR
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
	p := startPeer(t, python, role, transfer)

	var s *edhoc.Session
	if goInitiates {
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
		s, err = i.Session()
		if err != nil {
			t.Fatal(err)
		}
	} else {
		r, err := edhoc.NewResponder(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.ReadMessage1(t.Context(), p.recv()); err != nil {
			t.Fatal(err)
		}
		msg2, err := r.WriteMessage2([]byte{0x05})
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
		s, err = r.Session()
		if err != nil {
			t.Fatal(err)
		}
	}

	compare := func(name string, label, length int) {
		t.Helper()
		got := p.recv()
		want, err := s.Exporter(label, nil, length)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: lakers %x, Go %x", name, got, want)
		}
	}
	compare("OSCORE master secret", 0, 16)
	compare("OSCORE master salt", 1, 8)
	if err := s.KeyUpdate(ctx); err != nil {
		t.Fatal(err)
	}
	compare("master secret after key update", 0, 16)
}
