package edhoc

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/aquilliam/edhoc/internal/cbor"
	"github.com/aquilliam/edhoc/internal/suites"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// lookup returns a PeerCredential function that knows the given credentials.
func lookup(creds ...Credential) func(context.Context, *PeerInfo) (Credential, error) {
	return func(_ context.Context, p *PeerInfo) (Credential, error) {
		for _, c := range creds {
			if c.ID == p.ID {
				return c, nil
			}
		}
		return Credential{}, ErrUnknownCredential
	}
}

type traceSetup struct {
	tr           func(string) []byte
	credI, credR Credential
	cfgI, cfgR   *Config
	cI, cR       []byte
}

// newTrace2 sets up both sides with the keys and credentials of RFC 9529,
// Section 3.
func newTrace2(t testing.TB) *traceSetup {
	tr := trace2(t)
	credI, err := ParseCCS(tr("CRED_I (CBOR Data Item)"))
	if err != nil {
		t.Fatal(err)
	}
	credR, err := ParseCCS(tr("CRED_R (CBOR Data Item)"))
	if err != nil {
		t.Fatal(err)
	}
	check(t, "ID_CRED_I", credI.ID.Bytes(), nil, tr("ID_CRED_I (CBOR Data Item)"))
	check(t, "ID_CRED_R", credR.ID.Bytes(), nil, tr("ID_CRED_R (CBOR Data Item)"))
	skI, err := ecdh.P256().NewPrivateKey(tr("SK_I (Raw Value)"))
	if err != nil {
		t.Fatal(err)
	}
	skR, err := ecdh.P256().NewPrivateKey(tr("SK_R (Raw Value)"))
	if err != nil {
		t.Fatal(err)
	}
	return &traceSetup{
		tr:    tr,
		cI:    tr("C_I (Raw Value)"),
		cR:    tr("C_R (raw value)"),
		credI: credI,
		credR: credR,
		cfgI: &Config{
			Method:         MethodStaticStatic,
			Suites:         []Suite{Suite2},
			Credential:     credI,
			Key:            skI,
			PeerCredential: lookup(credR),
		},
		cfgR: &Config{
			Method:         MethodStaticStatic,
			Suites:         []Suite{Suite2},
			Credential:     credR,
			Key:            skR,
			PeerCredential: lookup(credI),
		},
	}
}

func ephemeralKey(t testing.TB, raw []byte) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.P256().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestTrace2 runs the session of RFC 9529, Section 3 through the public API,
// with the ephemeral keys from the trace, and checks every message.
func TestTrace2(t *testing.T) {
	ts := newTrace2(t)
	tr := ts.tr

	// The Initiator first offers suite 6 alone, which the Responder does not
	// support. The trace gives no private key for that message_1's G_X, so it
	// is fed to the Responder as is.
	first := unhex(t, "03 06 5820 741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa9 0e")
	r, err := NewResponder(ts.cfgR)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.ReadMessage1(t.Context(), first)
	var e *Error
	if !errors.As(err, &e) || e.Code != ErrCodeWrongSelectedSuite {
		t.Fatalf("ReadMessage1(first message_1) error = %v, want a wrong-suite error", err)
	}
	check(t, "error", ErrorMessage(err), nil, tr("error (CBOR Sequence)"))

	// The Initiator receives the error.
	i, err := NewInitiator(ts.cfgI, ts.cI)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.WriteMessage1(); err != nil {
		t.Fatal(err)
	}
	_, err = i.ReadMessage2(t.Context(), tr("error (CBOR Sequence)"))
	var pe *PeerError
	if !errors.As(err, &pe) || pe.Code != ErrCodeWrongSelectedSuite || len(pe.Suites) != 1 || pe.Suites[0] != Suite2 {
		t.Fatalf("ReadMessage2(error) = %v, want SUITES_R = 2", err)
	}

	// Second attempt, with SUITES_I = [6, 2].
	cfgI := *ts.cfgI
	cfgI.Suites = []Suite{Suite6, Suite2}
	i, err = NewInitiator(&cfgI, ts.cI, pe.Suites...)
	if err != nil {
		t.Fatal(err)
	}
	i.h.eph = ephemeralKey(t, tr("X (Raw Value)"))
	msg1, err := i.WriteMessage1()
	check(t, "message_1", msg1, err, tr("message_1 (CBOR Sequence)"))

	r, err = NewResponder(ts.cfgR)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadMessage1(t.Context(), msg1); err != nil {
		t.Fatal(err)
	}
	r.h.eph = ephemeralKey(t, tr("Y (Raw Value)"))
	msg2, err := r.WriteMessage2(ts.cR)
	check(t, "message_2", msg2, err, tr("message_2 (CBOR Sequence)"))

	if _, err := i.ReadMessage2(t.Context(), msg2); err != nil {
		t.Fatal(err)
	}
	msg3, err := i.WriteMessage3()
	check(t, "message_3", msg3, err, tr("message_3 (CBOR Sequence)"))

	if _, err := r.ReadMessage3(t.Context(), msg3); err != nil {
		t.Fatal(err)
	}
	msg4, err := r.WriteMessage4()
	check(t, "message_4", msg4, err, tr("message_4 (CBOR Sequence)"))
	if _, err := i.ReadMessage4(msg4); err != nil {
		t.Fatal(err)
	}

	si, err := i.Session()
	if err != nil {
		t.Fatal(err)
	}
	sr, err := r.Session()
	if err != nil {
		t.Fatal(err)
	}
	check(t, "PRK_out", si.prkOut, nil, tr("PRK_out (Raw Value)"))
	check(t, "PRK_out", sr.prkOut, nil, tr("PRK_out (Raw Value)"))

	for _, step := range []string{"", " after KeyUpdate"} {
		if step != "" {
			for _, s := range []*Session{si, sr} {
				if err := s.KeyUpdate(tr("context for KeyUpdate (Raw Value)")); err != nil {
					t.Fatal(err)
				}
			}
		}
		oi, err := si.OSCORE()
		if err != nil {
			t.Fatal(err)
		}
		or, err := sr.OSCORE()
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range []*OSCOREParams{oi, or} {
			check(t, "OSCORE Master Secret"+step, o.MasterSecret, nil, tr("OSCORE Master Secret"+step+" (Raw Value)"))
			check(t, "OSCORE Master Salt"+step, o.MasterSalt, nil, tr("OSCORE Master Salt"+step+" (Raw Value)"))
			if o.AEADAlg != 10 || o.HashAlg != -16 {
				t.Errorf("OSCORE algorithms = %d, %d, want 10, -16", o.AEADAlg, o.HashAlg)
			}
		}
		check(t, "client Sender ID", oi.SenderID, nil, tr("Client's OSCORE Sender ID (Raw Value)"))
		check(t, "server Sender ID", or.SenderID, nil, tr("Server's OSCORE Sender ID (Raw Value)"))
		check(t, "client Recipient ID", oi.RecipientID, nil, or.SenderID)
		check(t, "server Recipient ID", or.RecipientID, nil, oi.SenderID)
	}
}

// newPair returns an Initiator and a Responder with fresh keys and
// credentials identified by kid.
func newPair(t *testing.T) (*Initiator, *Responder, *Config, *Config) {
	t.Helper()
	cred := func(kid byte) (Credential, *ecdh.PrivateKey) {
		k, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewCCS("", []byte{kid}, k.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		return c, k
	}
	credI, keyI := cred(0x2b)
	credR, keyR := cred(0x18)
	cfgI := &Config{
		Method:         MethodStaticStatic,
		Suites:         []Suite{Suite2},
		Credential:     credI,
		Key:            keyI,
		PeerCredential: lookup(credR),
	}
	cfgR := &Config{
		Method:         MethodStaticStatic,
		Suites:         []Suite{Suite2},
		Credential:     credR,
		Key:            keyR,
		PeerCredential: lookup(credI),
	}
	i, err := NewInitiator(cfgI, pairCI)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewResponder(cfgR)
	if err != nil {
		t.Fatal(err)
	}
	return i, r, cfgI, cfgR
}

// The connection identifiers newPair uses.
var pairCI, pairCR = []byte{0x0e}, []byte{0xab, 0xcd}

func run(t *testing.T, i *Initiator, r *Responder, ead1, ead2, ead3, ead4 []EAD) error {
	t.Helper()
	msg1, err := i.WriteMessage1(ead1...)
	if err != nil {
		return err
	}
	if _, err := r.ReadMessage1(t.Context(), msg1); err != nil {
		return err
	}
	msg2, err := r.WriteMessage2(pairCR, ead2...)
	if err != nil {
		return err
	}
	if _, err := i.ReadMessage2(t.Context(), msg2); err != nil {
		return err
	}
	msg3, err := i.WriteMessage3(ead3...)
	if err != nil {
		return err
	}
	if _, err := r.ReadMessage3(t.Context(), msg3); err != nil {
		return err
	}
	msg4, err := r.WriteMessage4(ead4...)
	if err != nil {
		return err
	}
	_, err = i.ReadMessage4(msg4)
	return err
}

func TestHandshake(t *testing.T) {
	i, r, _, _ := newPair(t)
	if err := run(t, i, r, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	si, _ := i.Session()
	sr, _ := r.Session()
	a, err := si.Exporter(42, []byte("ctx"), 20)
	if err != nil {
		t.Fatal(err)
	}
	b, err := sr.Exporter(42, []byte("ctx"), 20)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("the two sides exported different keys")
	}
	cI, cR := si.ConnIDs()
	if !bytes.Equal(cI, []byte{0x0e}) || !bytes.Equal(cR, []byte{0xab, 0xcd}) {
		t.Fatalf("ConnIDs = %x, %x", cI, cR)
	}
}

func TestEAD(t *testing.T) {
	i, r, cfgI, cfgR := newPair(t)
	cfgR.EADLabels = []int{7}
	cfgI.EADLabels = []int{7}
	pad := EAD{Label: 0, Value: []byte{1, 2, 3}}
	ead1 := []EAD{{Label: 5, Value: []byte("one")}, pad, {Label: -7}}
	ead2 := []EAD{{Label: 6, Value: []byte{}}}
	ead3 := []EAD{pad, {Label: -7, Value: []byte("three")}}
	ead4 := []EAD{{Label: 8}}
	msg1, _ := i.WriteMessage1(ead1...)
	m1, err := r.ReadMessage1(t.Context(), msg1)
	if err != nil {
		t.Fatal(err)
	}
	got := m1.EAD
	if len(got) != 2 || got[0].Label != 5 || string(got[0].Value) != "one" || got[1].Label != -7 || got[1].Value != nil {
		t.Fatalf("EAD_1 = %+v", got)
	}
	msg2, _ := r.WriteMessage2(pairCR, ead2...)
	got, err = i.ReadMessage2(t.Context(), msg2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Label != 6 || got[0].Value == nil || len(got[0].Value) != 0 {
		t.Fatalf("EAD_2 = %+v", got)
	}
	msg3, _ := i.WriteMessage3(ead3...)
	got, err = r.ReadMessage3(t.Context(), msg3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].Value) != "three" {
		t.Fatalf("EAD_3 = %+v", got)
	}
	msg4, _ := r.WriteMessage4(ead4...)
	got, err = i.ReadMessage4(msg4)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Label != 8 {
		t.Fatalf("EAD_4 = %+v", got)
	}
}

func TestUnknownCriticalEAD(t *testing.T) {
	i, r, _, _ := newPair(t)
	msg1, _ := i.WriteMessage1(EAD{Label: -9})
	_, err := r.ReadMessage1(t.Context(), msg1)
	var e *Error
	if !errors.As(err, &e) || e.Code != ErrCodeUnspecified {
		t.Fatalf("ReadMessage1 error = %v, want an unspecified error", err)
	}
	reply := ErrorMessage(err)
	if _, err := i.ReadMessage2(t.Context(), reply); err == nil || !strings.Contains(err.Error(), "critical EAD") {
		t.Fatalf("Initiator got %v from the error message", err)
	}
}

func TestUnknownCredential(t *testing.T) {
	i, r, cfgI, _ := newPair(t)
	cfgI.PeerCredential = lookup()
	msg1, _ := i.WriteMessage1()
	r.ReadMessage1(t.Context(), msg1)
	msg2, _ := r.WriteMessage2(pairCR)
	_, err := i.ReadMessage2(t.Context(), msg2)
	if !errors.Is(err, ErrUnknownCredential) {
		t.Fatalf("ReadMessage2 error = %v, want ErrUnknownCredential", err)
	}
	if got := ErrorMessage(err); !bytes.Equal(got, []byte{0x03, 0xf5}) {
		t.Fatalf("error message = %x, want 03f5", got)
	}
	if _, err := r.ReadMessage3(t.Context(), ErrorMessage(err)); err == nil {
		t.Fatal("Responder accepted an error message as message_3")
	} else if pe := (*PeerError)(nil); !errors.As(err, &pe) || pe.Code != ErrCodeUnknownCredential {
		t.Fatalf("ReadMessage3 error = %v, want a PeerError with code 3", err)
	}
}

func TestSameConnectionIDs(t *testing.T) {
	i, r, _, _ := newPair(t)
	msg1, _ := i.WriteMessage1()
	if _, err := r.ReadMessage1(t.Context(), msg1); err != nil {
		t.Fatal(err)
	}
	if _, err := r.WriteMessage2(pairCI); err == nil {
		t.Fatal("WriteMessage2 accepted C_R equal to C_I")
	}
	if _, err := r.WriteMessage2(pairCR); err != nil {
		t.Fatalf("WriteMessage2 after a rejected C_R: %v", err)
	}
}

func TestWrongState(t *testing.T) {
	i, r, _, _ := newPair(t)
	if _, err := i.WriteMessage3(); !errors.Is(err, ErrWrongState) {
		t.Fatalf("WriteMessage3 before message_1: %v", err)
	}
	if _, err := r.WriteMessage2(pairCR); !errors.Is(err, ErrWrongState) {
		t.Fatalf("WriteMessage2 before message_1: %v", err)
	}
	if _, err := i.Session(); !errors.Is(err, ErrWrongState) {
		t.Fatalf("Session before message_3: %v", err)
	}
	if ErrorMessage(ErrWrongState) != nil {
		t.Fatal("ErrorMessage replied to API misuse")
	}
	msg1, _ := i.WriteMessage1()
	if _, err := i.WriteMessage1(); !errors.Is(err, ErrWrongState) {
		t.Fatalf("second WriteMessage1: %v", err)
	}
	if _, err := r.ReadMessage1(t.Context(), msg1[:len(msg1)-1]); err == nil {
		t.Fatal("Responder accepted a truncated message_1")
	}
	if _, err := r.ReadMessage1(t.Context(), msg1); !errors.Is(err, ErrWrongState) {
		t.Fatalf("ReadMessage1 after a failure: %v", err)
	}
}

// TestTamperedMessages changes each byte of message_2, message_3 and
// message_4 in turn and checks that the receiver rejects it.
func TestTamperedMessages(t *testing.T) {
	// tamper runs a session, changing byte k of message n. It returns the
	// receiver's error, or nil and false once k is past the end of message n.
	tamper := func(n, k int) (error, bool) {
		i, r, _, _ := newPair(t)
		flip := func(m []byte, at int) bool {
			if at != n {
				return true
			}
			if k >= len(m) {
				return false
			}
			m[k] ^= 0x04
			return true
		}
		msg1, _ := i.WriteMessage1()
		if _, err := r.ReadMessage1(t.Context(), msg1); err != nil {
			t.Fatal(err)
		}
		msg2, _ := r.WriteMessage2(pairCR)
		if !flip(msg2, 2) {
			return nil, false
		}
		if _, err := i.ReadMessage2(t.Context(), msg2); err != nil || n == 2 {
			return err, true
		}
		msg3, _ := i.WriteMessage3()
		if !flip(msg3, 3) {
			return nil, false
		}
		if _, err := r.ReadMessage3(t.Context(), msg3); err != nil || n == 3 {
			return err, true
		}
		msg4, _ := r.WriteMessage4()
		if !flip(msg4, 4) {
			return nil, false
		}
		_, err := i.ReadMessage4(msg4)
		return err, true
	}
	for n := 2; n <= 4; n++ {
		for k := 0; ; k++ {
			err, ok := tamper(n, k)
			if !ok {
				break
			}
			if err == nil {
				t.Fatalf("message_%d with byte %d changed was accepted", n, k)
			}
		}
	}
}

// The invalid message_1 examples from RFC 9529, Section 4.
func TestInvalidMessage1(t *testing.T) {
	ts := newTrace2(t)
	tests := []struct {
		name, msg, want string
	}{
		{"array instead of sequence", "84 03 02 5820 741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa9 0e", "METHOD"},
		{"C_I as byte string", "03 02 5820 741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa9 41 0e", "C_I"},
		{"SUITES_I as one-element array", "03 81 02 5820 741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa9 0e", "SUITES_I"},
		{"G_X as text", "03 02 7820 206169722073706565642066206120756e6c6164656e207377616c6c6f7720 0e", "G_X"},
		{"x not reduced modulo p", "03 02 5820 ffffffff00000001000000000000000000000000ffffffffffffffffffffffff 0e", "G_X"},
		{"x not on the curve", "03 02 5820 a04e73601df544a70ba7ea1e57030f7d4b4eb7f673924e58d54ca77a5e7d4d4a 0e", "G_X"},
		{"G_X missing its leading zero", "03 02 581f d9697725d23a688b12d1c7e0108a08c9f71a85a09c20814976ab21122248fc 0e", "G_X"},
		{"METHOD in a two-byte integer", "19 0003 02 5820 741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa9 0e", "METHOD"},
		{"indefinite-length SUITES_I", "03 9f 06 02 ff 5820 741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa9 0e", "SUITES_I"},
		{"trailing byte string", "03 02 5820 741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa9 0e 41 00", "EAD_1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewResponder(ts.cfgR)
			if err != nil {
				t.Fatal(err)
			}
			_, err = r.ReadMessage1(t.Context(), unhex(t, tt.msg))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ReadMessage1 error = %v, want one about %s", err, tt.want)
			}
		})
	}
}

// The invalid message_2 and PLAINTEXT_2 examples from RFC 9529, Section 4.
func TestInvalidMessage2(t *testing.T) {
	ts := newTrace2(t)
	tr := ts.tr
	s, _ := suites.ByID(2)
	gY := tr("G_Y (Raw Value)")
	encrypt := func(pt []byte) []byte {
		ks, err := kdf(s, tr("PRK_2e (Raw Value)"), labelKeystream2, tr("TH_2 (Raw Value)"), len(pt))
		if err != nil {
			t.Fatal(err)
		}
		body := append(bytes.Clone(gY), make([]byte, len(pt))...)
		subtle.XORBytes(body[len(gY):], pt, ks)
		return cbor.AppendBytes(nil, body)
	}
	tests := []struct {
		name string
		msg  []byte
		want string
	}{
		{"two items", unhex(t, "5820 419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5 4b 9862a11de42a95d785386a"), "trailing data"},
		{"ID_CRED_R as a map with only a kid", encrypt(unhex(t, "27 a1 04 42 32 10 48 fa5efa2ebf920bf3")), "ID_CRED_R"},
		{"kid as a one-byte byte string", encrypt(unhex(t, "27 41 32 48 fa5efa2ebf920bf3")), "ID_CRED_R"},
		{"MAC too short", encrypt(unhex(t, "27 32 44 fa5efa2e")), "MAC"},
		{"correct layout, wrong MAC", encrypt(unhex(t, "27 32 48 0943305c899f5c55")), "MAC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgI := *ts.cfgI
			cfgI.Suites = []Suite{Suite6, Suite2}
			i, err := NewInitiator(&cfgI, ts.cI, Suite2)
			if err != nil {
				t.Fatal(err)
			}
			i.h.eph = ephemeralKey(t, tr("X (Raw Value)"))
			if _, err := i.WriteMessage1(); err != nil {
				t.Fatal(err)
			}
			_, err = i.ReadMessage2(t.Context(), tt.msg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ReadMessage2 error = %v, want one about %s", err, tt.want)
			}
		})
	}
}

func TestPeerErrorMessages(t *testing.T) {
	tests := []struct {
		msg  string
		want PeerError
	}{
		{"01 63 616263", PeerError{Code: 1, Info: "abc"}},
		{"02 82 00 02", PeerError{Code: 2, Suites: []Suite{0, 2}}},
		{"03 f5", PeerError{Code: 3}},
		{"18 40 a0", PeerError{Code: 64}},
	}
	for _, tt := range tests {
		i, _, _, _ := newPair(t)
		i.WriteMessage1()
		_, err := i.ReadMessage2(t.Context(), unhex(t, tt.msg))
		var pe *PeerError
		if !errors.As(err, &pe) || pe.Code != tt.want.Code || pe.Info != tt.want.Info || len(pe.Suites) != len(tt.want.Suites) {
			t.Errorf("error message %s gave %v", tt.msg, err)
		}
	}
	for _, bad := range []string{"01 01", "02 81 02", "03", "01 63 616263 00"} {
		i, _, _, _ := newPair(t)
		i.WriteMessage1()
		_, err := i.ReadMessage2(t.Context(), unhex(t, bad))
		var pe *PeerError
		if err == nil || errors.As(err, &pe) {
			t.Errorf("malformed error message %s gave %v", bad, err)
		}
	}
}

func TestConfigChecks(t *testing.T) {
	_, _, base, _ := newPair(t)
	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"signature method", func(c *Config) { c.Method = MethodSignSign }},
		{"no suites", func(c *Config) { c.Suites = nil }},
		{"unsupported suite", func(c *Config) { c.Suites = []Suite{23} }},
		{"repeated suite", func(c *Config) { c.Suites = []Suite{2, 2} }},
		{"no credential", func(c *Config) { c.Credential.Raw = nil }},
		{"no ID_CRED", func(c *Config) { c.Credential.ID = IDCred{} }},
		{"no key", func(c *Config) { c.Key = nil }},
		{"key does not match credential", func(c *Config) { c.Key = other }},
		{"no PeerCredential", func(c *Config) { c.PeerCredential = nil }},
	}
	for _, tt := range tests {
		c := *base
		tt.edit(&c)
		if _, err := NewInitiator(&c, pairCI); err == nil {
			t.Errorf("%s: NewInitiator accepted the config", tt.name)
		}
		if _, err := NewResponder(&c); err == nil {
			t.Errorf("%s: NewResponder accepted the config", tt.name)
		}
	}
	c := *base
	if _, err := NewInitiator(&c, pairCI, Suite0); err == nil {
		t.Error("NewInitiator accepted peer suites with no suite in common")
	}

	// The P-256 key does not work with suite 0. The Initiator only needs a
	// key for the suite it selects; the Responder needs one for every suite.
	c.Suites = []Suite{Suite0, Suite2}
	if _, err := NewInitiator(&c, pairCI); err == nil {
		t.Error("NewInitiator selected a suite its key cannot be used with")
	}
	if _, err := NewInitiator(&c, pairCI, Suite2); err != nil {
		t.Errorf("NewInitiator with a key for the selected suite: %v", err)
	}
	if _, err := NewResponder(&c); err == nil {
		t.Error("NewResponder accepted a suite its key cannot be used with")
	}
}

func TestGetConfig(t *testing.T) {
	keyI0, credI0 := party(t, false, Suite0, 0x01)
	keyI2, credI2 := party(t, true, Suite2, 0x02)
	keyR0, credR0 := party(t, false, Suite0, 0x03)
	keyR2, credR2 := party(t, true, Suite2, 0x04)
	peers := lookup(credI0, credI2)
	byMethod := map[Method]*Config{
		MethodStaticStatic: {Method: MethodStaticStatic, Suites: []Suite{Suite0},
			Credential: credR0, Key: keyR0, PeerCredential: peers},
		MethodSignSign: {Method: MethodSignSign, Suites: []Suite{Suite2},
			Credential: credR2, Key: keyR2, PeerCredential: peers},
	}
	var got *Message1Info
	cfgR := &Config{Suites: []Suite{Suite0, Suite2}, GetConfig: func(ctx context.Context, m *Message1Info) (*Config, error) {
		got = m
		c, ok := byMethod[m.Method]
		if !ok {
			return nil, errors.New("method not accepted")
		}
		return c, nil
	}}
	clients := []*Config{
		{Method: MethodStaticStatic, Suites: []Suite{Suite0}, Credential: credI0, Key: keyI0,
			PeerCredential: lookup(credR0)},
		{Method: MethodSignSign, Suites: []Suite{Suite2}, Credential: credI2, Key: keyI2,
			PeerCredential: lookup(credR2)},
	}
	for _, cfgI := range clients {
		i, err := NewInitiator(cfgI, pairCI)
		if err != nil {
			t.Fatal(err)
		}
		r, err := NewResponder(cfgR)
		if err != nil {
			t.Fatal(err)
		}
		if err := run(t, i, r, []EAD{{Label: 0}, {Label: 9}}, nil, nil, nil); err != nil {
			t.Fatalf("%v: %v", cfgI.Method, err)
		}
		if got.Method != cfgI.Method || got.Suite != cfgI.Suites[0] || len(got.Suites) != 1 ||
			len(got.EAD) != 1 || got.EAD[0].Label != 9 || !bytes.Equal(got.PeerConnID, pairCI) {
			t.Errorf("%v: Message1Info = %+v", cfgI.Method, got)
		}
	}

	cfgI := *clients[0]
	cfgI.Method = MethodSignStatic
	cfgI.Key = keyI2
	cfgI.Credential = credI2
	cfgI.Suites = []Suite{Suite2}
	i, _ := NewInitiator(&cfgI, pairCI)
	r, _ := NewResponder(cfgR)
	msg1, _ := i.WriteMessage1()
	_, err := r.ReadMessage1(t.Context(), msg1)
	if err == nil || ErrorMessage(err) == nil {
		t.Fatalf("ReadMessage1 with a refused method: err = %v, want an error to send", err)
	}

	// Negotiation uses every suite in cfgR.Suites, so an Initiator that
	// prefers suite 0 but selects suite 2 is told to use suite 0.
	cfgI = *clients[1]
	cfgI.Suites = []Suite{Suite0, Suite2}
	i, _ = NewInitiator(&cfgI, pairCI, Suite2)
	r, _ = NewResponder(cfgR)
	msg1, _ = i.WriteMessage1()
	got = nil
	_, err = r.ReadMessage1(t.Context(), msg1)
	var e *Error
	if !errors.As(err, &e) || e.Code != ErrCodeWrongSelectedSuite || len(e.Suites) != 1 || e.Suites[0] != Suite0 || got != nil {
		t.Fatalf("ReadMessage1 with a less preferred suite: err = %v, GetConfig called: %v", err, got != nil)
	}

	// A Config without the selected suite is refused.
	byMethod[MethodSignSign] = byMethod[MethodStaticStatic]
	i, _ = NewInitiator(clients[1], pairCI)
	r, _ = NewResponder(cfgR)
	msg1, _ = i.WriteMessage1()
	if _, err := r.ReadMessage1(t.Context(), msg1); err == nil {
		t.Fatal("ReadMessage1 accepted a Config with another method and suite")
	}
}

func TestKeysErased(t *testing.T) {
	i, r, _, _ := newPair(t)
	msg1, _ := i.WriteMessage1()
	r.ReadMessage1(t.Context(), msg1)
	msg2, _ := r.WriteMessage2(pairCR)
	i.ReadMessage2(t.Context(), msg2)
	msg3, _ := i.WriteMessage3()
	if _, err := r.ReadMessage3(t.Context(), msg3); err != nil {
		t.Fatal(err)
	}
	for _, h := range []*handshake{&i.h, &r.h} {
		if h.eph != nil || h.prk2e != nil || h.prk3e2m != nil || h.prk4e3m == nil {
			t.Fatal("keys other than PRK_4e3m kept after message_3")
		}
	}
	msg4, _ := r.WriteMessage4()
	if _, err := i.ReadMessage4(msg4); err != nil {
		t.Fatal(err)
	}
	if i.h.prk4e3m != nil || r.h.prk4e3m != nil {
		t.Fatal("PRK_4e3m kept after message_4")
	}
}

func TestSessionClose(t *testing.T) {
	i, r, _, _ := newPair(t)
	if err := run(t, i, r, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	s, _ := i.Session()
	s.Close()
	if _, err := s.Exporter(0, nil, 16); !errors.Is(err, ErrWrongState) {
		t.Errorf("Exporter after Close: %v", err)
	}
	if _, err := s.OSCORE(); !errors.Is(err, ErrWrongState) {
		t.Errorf("OSCORE after Close: %v", err)
	}
	if err := s.KeyUpdate(nil); !errors.Is(err, ErrWrongState) {
		t.Errorf("KeyUpdate after Close: %v", err)
	}
}

func TestExporterAndOSCORELimits(t *testing.T) {
	i, r, _, _ := newPair(t)
	if err := run(t, i, r, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	s, _ := i.Session()
	if _, err := s.Exporter(0, nil, -1); err == nil {
		t.Error("Exporter accepted a negative length")
	}
	if _, err := s.Exporter(0, nil, 255*32+1); err == nil {
		t.Error("Exporter accepted a length above 255 hash lengths")
	}
	for _, tt := range []struct {
		suite Suite
		n     int
	}{{Suite2, 7}, {Suite4, 6}, {Suite24, 6}} {
		for _, n := range []int{tt.n, tt.n + 1} {
			id := make([]byte, n)
			s := &Session{suite: mustSuite(t, tt.suite), cI: id, cR: []byte{1}, prkOut: make([]byte, 32), prkExporter: make([]byte, 48)}
			_, err := s.OSCORE()
			if (err == nil) != (n == tt.n) {
				t.Errorf("%v with a %d-byte C_I: err = %v", tt.suite, n, err)
			}
		}
	}
}

func mustSuite(t *testing.T, id Suite) *suites.Suite {
	t.Helper()
	s, ok := suiteByID(id)
	if !ok {
		t.Fatalf("suite %d not supported", id)
	}
	return s
}

func TestPeerInfo(t *testing.T) {
	i, r, cfgI, cfgR := newPair(t)
	var gotI, gotR *PeerInfo
	wrap := func(f func(context.Context, *PeerInfo) (Credential, error), got **PeerInfo) func(context.Context, *PeerInfo) (Credential, error) {
		return func(ctx context.Context, p *PeerInfo) (Credential, error) {
			*got = p
			return f(ctx, p)
		}
	}
	cfgI.PeerCredential = wrap(cfgI.PeerCredential, &gotI)
	cfgR.PeerCredential = wrap(cfgR.PeerCredential, &gotR)
	ead2 := []EAD{{Label: 0}, {Label: 7, Value: []byte("two")}}
	ead3 := []EAD{{Label: 9, Value: []byte("three")}}
	if err := run(t, i, r, nil, ead2, ead3, nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name         string
		got          *PeerInfo
		id           IDCred
		ead          []EAD
		own, peerCID []byte
	}{
		{"Initiator", gotI, cfgR.Credential.ID, ead2[1:], pairCI, pairCR},
		{"Responder", gotR, cfgI.Credential.ID, ead3, pairCR, pairCI},
	} {
		if c.got == nil {
			t.Fatalf("%s: PeerCredential was not called", c.name)
		}
		if c.got.ID != c.id || !bytes.Equal(c.got.ConnID, c.own) || !bytes.Equal(c.got.PeerConnID, c.peerCID) {
			t.Errorf("%s: PeerInfo = %+v", c.name, c.got)
		}
		if len(c.got.EAD) != len(c.ead) || c.got.EAD[0].Label != c.ead[0].Label || !bytes.Equal(c.got.EAD[0].Value, c.ead[0].Value) {
			t.Errorf("%s: PeerInfo.EAD = %+v, want %+v", c.name, c.got.EAD, c.ead)
		}
	}
}

func TestSessionConcurrentUse(t *testing.T) {
	i, r, _, _ := newPair(t)
	if err := run(t, i, r, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	s, _ := i.Session()
	var wg sync.WaitGroup
	for n := range 8 {
		wg.Go(func() {
			if n%2 == 0 {
				if err := s.KeyUpdate([]byte{byte(n)}); err != nil {
					t.Error(err)
				}
				return
			}
			if _, err := s.OSCORE(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

func TestPeerCredentialContext(t *testing.T) {
	i, r, cfgI, _ := newPair(t)
	type key struct{}
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), key{}, "session"))
	lookUp := cfgI.PeerCredential
	cfgI.PeerCredential = func(ctx context.Context, p *PeerInfo) (Credential, error) {
		if ctx.Value(key{}) != "session" {
			t.Error("PeerCredential did not get the context passed to ReadMessage2")
		}
		if err := ctx.Err(); err != nil {
			return Credential{}, err
		}
		return lookUp(ctx, p)
	}
	msg1, _ := i.WriteMessage1()
	if _, err := r.ReadMessage1(t.Context(), msg1); err != nil {
		t.Fatal(err)
	}
	msg2, _ := r.WriteMessage2(pairCR)
	cancel()
	_, err := i.ReadMessage2(ctx, msg2)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadMessage2 error = %v, want one wrapping context.Canceled", err)
	}
	if m := ErrorMessage(err); bytes.Contains(m, []byte("canceled")) {
		t.Errorf("error message to the peer reveals the local error: %q", m)
	}
}

func TestStrings(t *testing.T) {
	for _, tt := range []struct {
		got  fmt.Stringer
		want string
	}{
		{MethodSignStatic, "sign-static"},
		{Method(9), "method 9"},
		{Suite2, "suite 2 (AES-CCM-16-64-128, SHA-256, 8, P-256, ES256)"},
		{Suite(23), "suite 23"},
		{ErrCodeUnknownCredential, "unknown credential referenced"},
		{ErrCode(-5), "error code -5"},
	} {
		if s := tt.got.String(); s != tt.want {
			t.Errorf("String() = %q, want %q", s, tt.want)
		}
	}
	if _, err := (&Initiator{}).Session(); !errors.Is(err, ErrWrongState) {
		t.Errorf("Session before the handshake: %v, want ErrWrongState", err)
	}
}

func TestOversizedEAD(t *testing.T) {
	i, r, _, _ := newPair(t)
	msg1, _ := i.WriteMessage1()
	r.ReadMessage1(t.Context(), msg1)
	msg2, _ := r.WriteMessage2(pairCR)
	i.ReadMessage2(t.Context(), msg2)
	if _, err := i.WriteMessage3(EAD{Label: 5, Value: make([]byte, 1<<16)}); err == nil {
		t.Fatal("WriteMessage3 accepted an EAD_3 too long for AES-CCM")
	}
}

func TestApplicationError(t *testing.T) {
	msg := ErrorMessage(&Error{Code: ErrCodeUnspecified, Info: "EAD item 5 rejected"})
	var pe *PeerError
	if err := parseErrorMessage(msg); !errors.As(err, &pe) || pe.Code != ErrCodeUnspecified || pe.Info != "EAD item 5 rejected" {
		t.Fatalf("parsed %x as %v", msg, err)
	}
	if err := parseErrorMessage(ErrorMessage(&Error{Code: ErrCodeUnspecified, Info: "\xff"})); !errors.As(err, &pe) || pe.Info != "" {
		t.Fatalf("invalid UTF-8 Info: %v", err)
	}
}
