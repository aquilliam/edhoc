package edhoc

import (
	"bytes"
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

func TestIDCredByValue(t *testing.T) {
	a, b := []byte{0x30, 0x01}, []byte{0x30, 0x02}
	for _, certs := range [][][]byte{{a}, {a, b}} {
		id := X5Chain(certs...)
		got, ok := id.X5Chain()
		if !ok || len(got) != len(certs) || !bytes.Equal(got[0], a) {
			t.Errorf("X5Chain round trip of %d certificates: %x, %v", len(certs), got, ok)
		}
		if _, ok := id.KeyID(); ok {
			t.Error("KeyID accepted an x5chain")
		}
	}
	one, _ := ParseIDCred([]byte{0xa1, 0x18, 0x21, 0x81, 0x42, 0x30, 0x01})
	if got, ok := one.X5Chain(); !ok || len(got) != 1 || !bytes.Equal(got[0], a) {
		t.Errorf("X5Chain of a one-element array: %x, %v", got, ok)
	}
	if got := X5Chain(a).Bytes(); !bytes.Equal(got, []byte{0xa1, 0x18, 0x21, 0x42, 0x30, 0x01}) {
		t.Errorf("X5Chain(a) = %x", got)
	}

	ccs := []byte{0xa1, 0x02, 0x60}
	id := KCCS(ccs)
	if !bytes.Equal(id.Bytes(), []byte{0xa1, 0x0e, 0xa1, 0x02, 0x60}) {
		t.Errorf("KCCS = %x", id.Bytes())
	}
	if got, ok := id.KCCS(); !ok || !bytes.Equal(got, ccs) {
		t.Errorf("KCCS round trip: %x, %v", got, ok)
	}
	if _, ok := id.X5Chain(); ok {
		t.Error("X5Chain accepted a kccs")
	}

	for _, raw := range []string{
		"a1182180",         // { 33 : [] }
		"a11821824230010a", // { 33 : [h'3001', 10] }
		"a10e42a100",       // { 14 : h'a100' }
		"a2044101182142",   // { 4 : h'01', 33 : ... } is not a single entry
	} {
		id, err := ParseIDCred(unhex(t, raw))
		if err != nil {
			continue
		}
		if _, ok := id.X5Chain(); ok {
			t.Errorf("X5Chain accepted %s", raw)
		}
		if _, ok := id.KCCS(); ok {
			t.Errorf("KCCS accepted %s", raw)
		}
	}
}
