package edhoc

import (
	"crypto/ecdh"
	"testing"

	"github.com/aquilliam/edhoc/internal/cbor"
)

func TestNewCCSMatchesTrace2(t *testing.T) {
	tr := trace2(t)
	for _, side := range []struct {
		sk, cred, subject string
		kid               byte
	}{
		{"SK_R (Raw Value)", "CRED_R (CBOR Data Item)", "example.edu", 0x32},
		{"SK_I (Raw Value)", "CRED_I (CBOR Data Item)", "42-50-31-FF-EF-37-32-39", 0x2b},
	} {
		k, err := ecdh.P256().NewPrivateKey(tr(side.sk))
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewCCS(side.subject, []byte{side.kid}, k.PublicKey())
		check(t, side.cred, c.Raw, err, tr(side.cred))
		parsed, err := ParseCCS(c.Raw)
		if err != nil {
			t.Fatal(err)
		}
		if !parsed.ID.Equal(c.ID) || !parsed.PublicKey.(*ecdh.PublicKey).Equal(k.PublicKey()) {
			t.Fatalf("ParseCCS(NewCCS(...)) gave a different credential")
		}
	}
}

func TestParseCCSRejects(t *testing.T) {
	for _, in := range []string{
		"",
		"a0",                                  // no cnf
		"a1 08 a0",                            // no COSE_Key
		"a1 08 a1 01 a2 01 01 20 04",          // OKP key
		"a1 08 a1 01 a3 01 02 20 01 21 41 00", // EC2 without y
		"a2 08 a0 02 60",                      // keys out of order
		"a1 08 a1 01 a2 01 02 20 01 00",       // trailing data
	} {
		if _, err := ParseCCS(unhex(t, in)); err == nil {
			t.Errorf("ParseCCS(%s) succeeded", in)
		}
	}
}

func FuzzReadIDCred(f *testing.F) {
	f.Add([]byte{0x32})
	f.Add([]byte{0x41, 0x18})
	f.Add([]byte{0xa1, 0x22, 0x82, 0x2e, 0x48, 1, 2, 3, 4, 5, 6, 7, 8})
	f.Fuzz(func(t *testing.T, data []byte) {
		id, err := readIDCred(cbor.NewDecoder(data))
		if err != nil {
			return
		}
		again, err := readIDCred(cbor.NewDecoder(id.appendCompact(nil)))
		if err != nil || !again.Equal(id) {
			t.Fatalf("ID_CRED %x did not survive a round trip: %v", id.raw, err)
		}
	})
}
