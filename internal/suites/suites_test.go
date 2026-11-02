package suites

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Values from RFC 9529, Section 3 (method 3, cipher suite 2).
const (
	traceX    = "368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525"
	traceGX   = "8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6"
	traceY    = "e2f4126777205e853b437d6eaca1e1f753cdcc3e2c69fa884b0a1a640977e418"
	traceGY   = "419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5"
	traceGXY  = "2f0cb7e860ba538fbf5c8bded009f6259b4b628fe1eb7dbe9378e5ecf7a824ba"
	traceSKR  = "72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac"
	traceGRX  = "f2b6eea02220b95eee5a0bc701f074e00a843ea02422f60825fb269b3e161423"
	traceSKI  = "fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b"
	traceGIY  = "080f425085bc6249089eac8f108ea62326857e12ab07d72028ca1b5f36e004b3"
	traceK3   = "8e7a30042000f7900e8174131f75f3ed"
	traceIV3  = "6d8300c1e23b56153ae70ee457"
	traceA3   = "8368456e63727970743040" + "5820adaf67a78a4bcc91e018f8882762a722000b2507039df0bc1bbf0c161bb3155c"
	traceP3   = "2b48623c91df41e34c2f"
	traceC3   = "e562097bc417dd5919485ac7891ffd90a9fc"
	traceK4   = "d3c77872b6eeb508911bdbd308b2e6a0"
	traceIV4  = "04ff0f44456e96e217853c3601"
	traceA4   = "8368456e63727970743040" + "5820c902b1e3a4326c93c5551f5f3aa6c5ecc0246806765612e52b5d99e6059d6b6e"
	traceC4   = "28c966b7ca304f83"
	tracePKRX = "bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0"
)

// TestRegistry checks each suite against RFC 9528, Table 6.
func TestRegistry(t *testing.T) {
	for _, want := range []struct {
		id, aead, keySize, tagSize, hashLength, macLength, pubSize, sigAlg, appAEAD, appHash int
	}{
		{0, 10, 16, 8, 32, 8, 32, AlgEdDSA, 10, -16},
		{1, 30, 16, 16, 32, 16, 32, AlgEdDSA, 10, -16},
		{2, 10, 16, 8, 32, 8, 32, AlgES256, 10, -16},
		{3, 30, 16, 16, 32, 16, 32, AlgES256, 10, -16},
	} {
		s, ok := ByID(want.id)
		if !ok {
			t.Errorf("suite %d not found", want.id)
			continue
		}
		got := [...]int{s.KeySize, s.TagSize, s.HashLength(), s.MACLength, s.PublicKeySize(), s.SigAlg, s.AppAEAD, s.AppHash}
		exp := [...]int{want.keySize, want.tagSize, want.hashLength, want.macLength, want.pubSize, want.sigAlg, want.appAEAD, want.appHash}
		if got != exp {
			t.Errorf("suite %d: got %v, want %v", want.id, got, exp)
		}
		key := make([]byte, s.KeySize)
		a, err := s.AEAD(key)
		if err != nil {
			t.Fatal(err)
		}
		if a.NonceSize() != s.NonceSize || a.Overhead() != s.TagSize {
			t.Errorf("suite %d: AEAD has nonce size %d and overhead %d", want.id, a.NonceSize(), a.Overhead())
		}
	}
	if _, ok := ByID(23); ok {
		t.Error("ByID(23) found a reserved suite")
	}
}

func TestTraceKeyExchange(t *testing.T) {
	s, _ := ByID(2)
	ecdhWith := func(priv, pubX string) []byte {
		t.Helper()
		k, err := s.Curve.NewPrivateKey(unhex(t, priv))
		if err != nil {
			t.Fatal(err)
		}
		pub, err := s.ParsePublicKey(unhex(t, pubX))
		if err != nil {
			t.Fatal(err)
		}
		z, err := k.ECDH(pub)
		if err != nil {
			t.Fatal(err)
		}
		return z
	}
	compact := func(priv string) string {
		k, err := s.Curve.NewPrivateKey(unhex(t, priv))
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(s.CompactPublicKey(k.PublicKey()))
	}

	if got := compact(traceX); got != traceGX {
		t.Errorf("G_X = %s, want %s", got, traceGX)
	}
	if got := compact(traceY); got != traceGY {
		t.Errorf("G_Y = %s, want %s", got, traceGY)
	}
	if got := compact(traceSKR); got != tracePKRX {
		t.Errorf("G_R = %s, want %s", got, tracePKRX)
	}
	tests := []struct {
		name, priv, pub, want string
	}{
		{"G_XY from Y", traceY, traceGX, traceGXY},
		{"G_XY from X", traceX, traceGY, traceGXY},
		{"G_RX from R", traceSKR, traceGX, traceGRX},
		{"G_RX from X", traceX, tracePKRX, traceGRX},
		{"G_IY from Y", traceY, compact(traceSKI), traceGIY},
		{"G_IY from I", traceSKI, traceGY, traceGIY},
	}
	for _, tt := range tests {
		if got := hex.EncodeToString(ecdhWith(tt.priv, tt.pub)); got != tt.want {
			t.Errorf("%s = %s, want %s", tt.name, got, tt.want)
		}
	}
}

// G_X values from the invalid traces in RFC 9529, Section 4.2.
func TestParsePublicKeyRejectsInvalidPoints(t *testing.T) {
	s, _ := ByID(2)
	tests := []struct {
		name, x string
	}{
		{"x not reduced modulo p", "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"},
		{"x not on the curve", "a04e73601df544a70ba7ea1e57030f7d4b4eb7f673924e58d54ca77a5e7d4d4a"},
		{"leading zero byte missing", "d9697725d23a688b12d1c7e0108a08c9f71a85a09c20814976ab21122248fc"},
		{"empty", ""},
		{"uncompressed point", "04" + traceGX + traceGX},
	}
	for _, tt := range tests {
		if _, err := s.ParsePublicKey(unhex(t, tt.x)); err == nil {
			t.Errorf("%s: ParsePublicKey accepted %s", tt.name, tt.x)
		}
	}
}

func TestParsePublicKeyRoundTrip(t *testing.T) {
	s, _ := ByID(2)
	for range 64 {
		k, err := s.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		x := s.CompactPublicKey(k.PublicKey())
		pub, err := s.ParsePublicKey(x)
		if err != nil {
			t.Fatalf("ParsePublicKey(%x): %v", x, err)
		}
		if !bytes.Equal(s.CompactPublicKey(pub), x) {
			t.Fatalf("x-coordinate changed: %x -> %x", x, s.CompactPublicKey(pub))
		}
		other, _ := s.GenerateKey()
		z1, err1 := other.ECDH(pub)
		z2, err2 := other.ECDH(k.PublicKey())
		if err1 != nil || err2 != nil || !bytes.Equal(z1, z2) {
			t.Fatalf("ECDH with the recovered point differs: %v %v", err1, err2)
		}
	}
}

func TestTraceAEAD(t *testing.T) {
	s, _ := ByID(2)
	tests := []struct {
		name, key, iv, aad, pt, ct string
	}{
		{"message_3", traceK3, traceIV3, traceA3, traceP3, traceC3},
		{"message_4", traceK4, traceIV4, traceA4, "", traceC4},
	}
	for _, tt := range tests {
		a, err := s.AEAD(unhex(t, tt.key))
		if err != nil {
			t.Fatal(err)
		}
		got := a.Seal(nil, unhex(t, tt.iv), unhex(t, tt.pt), unhex(t, tt.aad))
		if hex.EncodeToString(got) != tt.ct {
			t.Errorf("%s: CIPHERTEXT = %x, want %s", tt.name, got, tt.ct)
		}
	}
	if _, err := s.AEAD(make([]byte, 32)); err == nil {
		t.Error("AEAD accepted a 32-byte key")
	}
}

func TestSignVerify(t *testing.T) {
	s, _ := ByID(2)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("Signature1")
	sig, err := s.Sign(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want 64", len(sig))
	}
	if !s.Verify(&key.PublicKey, msg, sig) {
		t.Fatal("Verify rejected a fresh signature")
	}
	if s.Verify(&key.PublicKey, []byte("Signature2"), sig) {
		t.Fatal("Verify accepted a signature over a different message")
	}
	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	if s.Verify(other.PublicKey(), msg, sig) {
		t.Fatal("Verify accepted a non-ECDSA public key")
	}
}

func TestWycheproofES256(t *testing.T) {
	data, err := os.ReadFile("testdata/ecdsa_secp256r1_sha256_p1363_test.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		NumberOfTests int
		TestGroups    []struct {
			PublicKey struct{ Uncompressed string }
			Sha       string
			Tests     []struct {
				TcID             int
				Comment          string
				Msg, Sig, Result string
			}
		}
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	s, _ := ByID(2)
	ran := 0
	for _, g := range file.TestGroups {
		if g.Sha != "SHA-256" {
			t.Fatalf("unexpected hash %s", g.Sha)
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), unhex(t, g.PublicKey.Uncompressed))
		if err != nil {
			ran += len(g.Tests)
			for _, tc := range g.Tests {
				if tc.Result == "valid" {
					t.Errorf("test %d: public key rejected: %v", tc.TcID, err)
				}
			}
			continue
		}
		for _, tc := range g.Tests {
			ran++
			ok := s.Verify(pub, unhex(t, tc.Msg), unhex(t, tc.Sig))
			switch tc.Result {
			case "valid":
				if !ok {
					t.Errorf("test %d (%s): valid signature rejected", tc.TcID, tc.Comment)
				}
			case "invalid":
				if ok {
					t.Errorf("test %d (%s): invalid signature accepted", tc.TcID, tc.Comment)
				}
			}
		}
	}
	if ran != file.NumberOfTests {
		t.Fatalf("ran %d tests, file has %d", ran, file.NumberOfTests)
	}
}

func readTrace1(t *testing.T) func(string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../testdata/rfc9529_trace1.json")
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
		return unhex(t, v)
	}
}

// Values from RFC 9529, Section 2 (method 0, cipher suite 0).
func TestSuite0Trace1(t *testing.T) {
	tr := readTrace1(t)
	s, ok := ByID(0)
	if !ok {
		t.Fatal("suite 0 not found")
	}
	if s.PublicKeySize() != 32 || s.SigAlg != AlgEdDSA || s.MACLength != 8 {
		t.Fatalf("suite 0 parameters do not match RFC 9528, Section 10.2: %+v", s)
	}
	x, err := s.Curve.NewPrivateKey(tr("X (Raw Value)"))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.CompactPublicKey(x.PublicKey()); !bytes.Equal(got, tr("G_X (Raw Value)")) {
		t.Fatalf("G_X = %x", got)
	}
	gY, err := s.ParsePublicKey(tr("G_Y (Raw Value)"))
	if err != nil {
		t.Fatal(err)
	}
	gXY, err := x.ECDH(gY)
	if err != nil || !bytes.Equal(gXY, tr("G_XY (Raw Value)")) {
		t.Fatalf("G_XY = %x, %v", gXY, err)
	}

	for _, side := range []struct{ sk, pk, msg, sig string }{
		{"SK_R (Raw Value)", "PK_R (Raw Value)", "Message to be signed in message_2 (CBOR Data Item)", "Signature_or_MAC_2 (Raw Value)"},
		{"SK_I (Raw Value)", "PK_I (Raw Value)", "Message to be signed in message_3 (CBOR Data Item)", "Signature_or_MAC_3 (Raw Value)"},
	} {
		key := ed25519.NewKeyFromSeed(tr(side.sk))
		if !bytes.Equal(key.Public().(ed25519.PublicKey), tr(side.pk)) {
			t.Fatalf("%s does not match %s", side.pk, side.sk)
		}
		sig, err := s.Sign(key, tr(side.msg))
		if err != nil || !bytes.Equal(sig, tr(side.sig)) {
			t.Fatalf("signature = %x, %v, want %x", sig, err, tr(side.sig))
		}
		if !s.Verify(ed25519.PublicKey(tr(side.pk)), tr(side.msg), sig) {
			t.Fatal("Verify rejected the trace signature")
		}
		if s.Verify(ed25519.PublicKey(tr(side.pk)), append(tr(side.msg), 0), sig) {
			t.Fatal("Verify accepted a signature over a different message")
		}
	}
}

// RFC 9529, Section 4.2.4: an X25519 point of low order.
func TestX25519LowOrderPoint(t *testing.T) {
	s, _ := ByID(0)
	pub, err := s.ParsePublicKey(unhex(t, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))
	if err != nil {
		return
	}
	k, _ := s.GenerateKey()
	if _, err := k.ECDH(pub); err == nil {
		t.Fatal("ECDH with a low-order X25519 point succeeded")
	}
}
