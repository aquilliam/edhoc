package edhoc

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/aquilliam/edhoc/internal/suites"
)

var allSuites = []Suite{Suite0, Suite1, Suite2, Suite3}

func trace1(t *testing.T) func(string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/rfc9529_trace1.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return func(name string) []byte {
		t.Helper()
		v, ok := m[name]
		if !ok {
			t.Fatalf("no value %q in trace 1", name)
		}
		b, err := hex.DecodeString(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
}

// TestTrace1 runs the session of RFC 9529, Section 2: method 0, cipher suite
// 0, X.509 certificates identified by x5t.
func TestTrace1(t *testing.T) {
	tr := trace1(t)
	credI, err := NewX509(tr("CRED_I (Raw Value)"))
	if err != nil {
		t.Fatal(err)
	}
	credR, err := NewX509(tr("CRED_R (Raw Value)"))
	if err != nil {
		t.Fatal(err)
	}
	check(t, "ID_CRED_I", credI.ID.Bytes(), nil, tr("ID_CRED_I (CBOR Data Item)"))
	check(t, "ID_CRED_R", credR.ID.Bytes(), nil, tr("ID_CRED_R (CBOR Data Item)"))
	check(t, "CRED_R", credR.Raw, nil, tr("CRED_R (CBOR Data Item)"))

	i, err := NewInitiator(&Config{
		Method:         MethodSignSign,
		Suites:         []Suite{Suite0},
		ConnID:         tr("C_I (Raw Value)"),
		Credential:     credI,
		Key:            ed25519.NewKeyFromSeed(tr("SK_I (Raw Value)")),
		PeerCredential: lookup(credR),
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewResponder(&Config{
		Method:         MethodSignSign,
		Suites:         []Suite{Suite0},
		ConnID:         tr("C_R (Raw Value)"),
		Credential:     credR,
		Key:            ed25519.NewKeyFromSeed(tr("SK_R (Raw Value)")),
		PeerCredential: lookup(credI),
	})
	if err != nil {
		t.Fatal(err)
	}
	x, err := ecdh.X25519().NewPrivateKey(tr("X (Raw Value)"))
	if err != nil {
		t.Fatal(err)
	}
	y, err := ecdh.X25519().NewPrivateKey(tr("Y (Raw Value)"))
	if err != nil {
		t.Fatal(err)
	}
	i.h.eph, r.h.eph = x, y

	msg1, err := i.WriteMessage1()
	check(t, "message_1", msg1, err, tr("message_1 (CBOR Sequence)"))
	if err := r.ReadMessage1(msg1); err != nil {
		t.Fatal(err)
	}
	msg2, err := r.WriteMessage2()
	check(t, "message_2", msg2, err, tr("message_2 (CBOR Sequence)"))
	if err := i.ReadMessage2(msg2); err != nil {
		t.Fatal(err)
	}
	msg3, err := i.WriteMessage3()
	check(t, "message_3", msg3, err, tr("message_3 (CBOR Sequence)"))
	if err := r.ReadMessage3(msg3); err != nil {
		t.Fatal(err)
	}
	msg4, err := r.WriteMessage4()
	check(t, "message_4", msg4, err, tr("message_4 (CBOR Sequence)"))
	if err := i.ReadMessage4(msg4); err != nil {
		t.Fatal(err)
	}
	si, _ := i.Session()
	sr, _ := r.Session()
	check(t, "PRK_out", si.prkOut, nil, tr("PRK_out (Raw Value)"))
	for _, s := range []*Session{si, sr} {
		o, err := s.OSCORE()
		if err != nil {
			t.Fatal(err)
		}
		check(t, "OSCORE Master Secret", o.MasterSecret, nil, tr("OSCORE Master Secret (Raw Value)"))
		check(t, "OSCORE Master Salt", o.MasterSalt, nil, tr("OSCORE Master Salt (Raw Value)"))
	}
	if o, _ := si.OSCORE(); hex.EncodeToString(o.SenderID) != hex.EncodeToString(tr("Client's OSCORE Sender ID (Raw Value)")) {
		t.Fatalf("client Sender ID = %x", o.SenderID)
	}
}

// party returns a key and credential for one side of a session with the
// given method and suite.
func party(t *testing.T, signs bool, suite Suite, kid byte) (any, Credential) {
	t.Helper()
	s, ok := suiteByID(suite)
	if !ok {
		t.Fatalf("suite %d not supported", suite)
	}
	var key any
	var pub crypto.PublicKey
	switch {
	case signs && s.SigAlg == suites.AlgEdDSA:
		p, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, pub = k, p
	case signs && s.SigAlg == suites.AlgES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, pub = k, &k.PublicKey
	case signs:
		t.Fatalf("no test key for signature algorithm %d", s.SigAlg)
	default:
		k, err := s.Curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, pub = k, k.PublicKey()
	}
	cred, err := NewCCS("", []byte{kid}, pub)
	if err != nil {
		t.Fatal(err)
	}
	return key, cred
}

func TestMethodsAndSuites(t *testing.T) {
	for _, suite := range allSuites {
		for m := MethodSignSign; m <= MethodStaticStatic; m++ {
			t.Run(fmt.Sprintf("suite %d method %d", suite, m), func(t *testing.T) {
				keyI, credI := party(t, m.initiatorSigns(), suite, 0x01)
				keyR, credR := party(t, m.responderSigns(), suite, 0x02)
				parsedI, err := ParseCCS(credI.Raw)
				if err != nil {
					t.Fatal(err)
				}
				parsedR, err := ParseCCS(credR.Raw)
				if err != nil {
					t.Fatal(err)
				}
				cfgI := &Config{Method: m, Suites: []Suite{suite}, ConnID: []byte{0x0e},
					Credential: credI, Key: keyI, PeerCredential: lookup(parsedR)}
				cfgR := &Config{Method: m, Suites: []Suite{suite}, ConnID: []byte{0x07},
					Credential: credR, Key: keyR, PeerCredential: lookup(parsedI)}
				newSides := func() (*Initiator, *Responder) {
					i, err := NewInitiator(cfgI)
					if err != nil {
						t.Fatal(err)
					}
					r, err := NewResponder(cfgR)
					if err != nil {
						t.Fatal(err)
					}
					return i, r
				}
				i, r := newSides()
				if err := run(t, i, r, nil, nil, nil, nil); err != nil {
					t.Fatal(err)
				}
				si, _ := i.Session()
				sr, _ := r.Session()
				a, _ := si.Exporter(0, nil, 16)
				b, _ := sr.Exporter(0, nil, 16)
				if hex.EncodeToString(a) != hex.EncodeToString(b) {
					t.Fatal("the two sides derived different keys")
				}

				// A Signature_or_MAC from someone without the private key is
				// rejected.
				_, imposter := party(t, m.responderSigns(), suite, 0x02)
				cfgI.PeerCredential = lookup(imposter)
				i, r = newSides()
				err = run(t, i, r, nil, nil, nil, nil)
				if err == nil {
					t.Fatal("Initiator accepted a Responder with a different key")
				}
				var e *Error
				if !errors.As(err, &e) {
					t.Fatalf("error %v is not an *Error", err)
				}
				cfgI.PeerCredential = lookup(parsedR)

				_, imposter = party(t, m.initiatorSigns(), suite, 0x01)
				cfgR.PeerCredential = lookup(imposter)
				i, r = newSides()
				if err := run(t, i, r, nil, nil, nil, nil); err == nil {
					t.Fatal("Responder accepted an Initiator with a different key")
				}
			})
		}
	}
}

func TestWrongKeyType(t *testing.T) {
	keyI, credI := party(t, true, Suite2, 0x01)
	keyR, credR := party(t, false, Suite2, 0x02)
	cfg := &Config{Method: MethodStaticStatic, Suites: []Suite{Suite2}, ConnID: []byte{1},
		Credential: credI, Key: keyI, PeerCredential: lookup(credR)}
	if _, err := NewInitiator(cfg); err == nil {
		t.Fatal("NewInitiator accepted a signing key for static DH")
	}
	cfg = &Config{Method: MethodSignSign, Suites: []Suite{Suite2}, ConnID: []byte{1},
		Credential: credR, Key: keyR, PeerCredential: lookup(credI)}
	if _, err := NewResponder(cfg); err == nil {
		t.Fatal("NewResponder accepted a DH key for signing")
	}
}
