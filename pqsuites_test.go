package edhoc

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func pqPair(t *testing.T) (*Initiator, *Responder) {
	t.Helper()
	keyI, credI := party(t, true, SuiteMinus24, 0x01)
	keyR, credR := party(t, true, SuiteMinus24, 0x02)
	i, err := NewInitiator(&Config{Method: MethodSignSign, Suites: []Suite{SuiteMinus24},
		Credential: credI, Key: keyI, PeerCredential: lookup(credR)}, pairCI)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewResponder(&Config{Method: MethodSignSign, Suites: []Suite{SuiteMinus24},
		Credential: credR, Key: keyR, PeerCredential: lookup(credI)})
	if err != nil {
		t.Fatal(err)
	}
	return i, r
}

func TestSuiteMinus24(t *testing.T) {
	i, r := pqPair(t)
	msg1, err := i.WriteMessage1()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadMessage1(t.Context(), msg1); err != nil {
		t.Fatal(err)
	}
	msg2, err := r.WriteMessage2(pairCR)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.ReadMessage2(t.Context(), msg2); err != nil {
		t.Fatal(err)
	}
	msg3, err := i.WriteMessage3()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadMessage3(t.Context(), msg3); err != nil {
		t.Fatal(err)
	}
	msg4, err := r.WriteMessage4()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.ReadMessage4(msg4); err != nil {
		t.Fatal(err)
	}
	t.Logf("message_1 %d bytes, message_2 %d, message_3 %d, message_4 %d", len(msg1), len(msg2), len(msg3), len(msg4))
	si, _ := i.Session()
	sr, _ := r.Session()
	oi, err := si.OSCORE()
	if err != nil {
		t.Fatal(err)
	}
	or, err := sr.OSCORE()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oi.MasterSecret, or.MasterSecret) || !bytes.Equal(oi.MasterSalt, or.MasterSalt) {
		t.Fatal("the two sides derived different OSCORE keys")
	}
	if len(si.prkOut) != 64 {
		t.Fatalf("PRK_out is %d bytes, want 64", len(si.prkOut))
	}
}

func TestSuiteMinus24Imposters(t *testing.T) {
	keyI, credI := party(t, true, SuiteMinus24, 0x01)
	keyR, credR := party(t, true, SuiteMinus24, 0x02)
	_, otherI := party(t, true, SuiteMinus24, 0x01)
	_, otherR := party(t, true, SuiteMinus24, 0x02)
	for _, tt := range []struct {
		name         string
		peerI, peerR Credential
	}{
		{"Responder", otherR, credI},
		{"Initiator", credR, otherI},
	} {
		i, err := NewInitiator(&Config{Method: MethodSignSign, Suites: []Suite{SuiteMinus24},
			Credential: credI, Key: keyI, PeerCredential: lookup(tt.peerI)}, pairCI)
		if err != nil {
			t.Fatal(err)
		}
		r, err := NewResponder(&Config{Method: MethodSignSign, Suites: []Suite{SuiteMinus24},
			Credential: credR, Key: keyR, PeerCredential: lookup(tt.peerR)})
		if err != nil {
			t.Fatal(err)
		}
		if err := run(t, i, r, nil, nil, nil, nil); err == nil {
			t.Errorf("a %s with a different key was accepted", tt.name)
		}
	}
}

func TestSuiteMinus24NeedsSignatures(t *testing.T) {
	sig, cred := party(t, true, SuiteMinus24, 0x01)
	dh, _ := ecdh.P256().GenerateKey(rand.Reader)
	for m := MethodSignStatic; m <= MethodStaticStatic; m++ {
		for _, initiator := range []bool{true, false} {
			signs := m.initiatorSigns()
			if !initiator {
				signs = m.responderSigns()
			}
			cfg := &Config{Method: m, Suites: []Suite{SuiteMinus24}, Credential: cred, Key: sig,
				PeerCredential: lookup(cred)}
			if !signs {
				cfg.Key = dh
				cfg.Credential.PublicKey = nil
			}
			var err error
			if initiator {
				_, err = NewInitiator(cfg, pairCI)
			} else {
				_, err = NewResponder(cfg)
			}
			if !signs && err == nil {
				t.Errorf("method %d: static DH accepted with suite -24 (initiator %v)", m, initiator)
			}
		}
	}
}

func TestSuiteMinus24BadKeyShares(t *testing.T) {
	i, r := pqPair(t)
	msg1, err := i.WriteMessage1()
	if err != nil {
		t.Fatal(err)
	}
	// METHOD and SUITES_I take one byte each, then G_X has a 3-byte header.
	if !bytes.Equal(msg1[2:5], []byte{0x59, 0x03, 0x20}) {
		t.Fatalf("unexpected message_1 layout %x", msg1[:5])
	}
	short := append(bytes.Clone(msg1[:2]), 0x59, 0x03, 0x1f)
	short = append(short, msg1[5:804]...)
	short = append(short, msg1[805:]...)
	if _, err := r.ReadMessage1(t.Context(), short); err == nil {
		t.Error("ReadMessage1 accepted a 799-byte G_X")
	}

	// Coefficients of t that are not reduced modulo q fail the FIPS 203
	// encapsulation key check.
	unreduced := bytes.Clone(msg1)
	for k := 5; k < 5+384; k++ {
		unreduced[k] = 0xff
	}
	_, r = pqPair(t)
	if _, err := r.ReadMessage1(t.Context(), unreduced); err == nil {
		t.Error("ReadMessage1 accepted an unreduced encapsulation key")
	}

	_, r = pqPair(t)
	if _, err := r.ReadMessage1(t.Context(), msg1); err != nil {
		t.Fatal(err)
	}
	msg2, err := r.WriteMessage2(pairCR)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte of G_Y, the 768-byte ciphertext at the start of the byte
	// string. Decapsulation then gives an unrelated secret.
	msg2[3+100] ^= 1
	if _, err := i.ReadMessage2(t.Context(), msg2); err == nil {
		t.Error("ReadMessage2 accepted a modified G_Y")
	}
}

func TestMLDSACCS(t *testing.T) {
	_, cred := party(t, true, SuiteMinus24, 0x07)
	parsed, err := ParseCCS(cred.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ID != cred.ID || !samePublicKey(parsed.PublicKey, cred.PublicKey) {
		t.Fatal("ParseCCS did not return the ML-DSA-44 credential it was given")
	}
}
