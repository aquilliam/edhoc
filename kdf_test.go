package edhoc

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/aquilliam/edhoc/internal/suites"
)

// trace2 returns a function that looks up values from RFC 9529, Section 3.
func trace2(t *testing.T) func(string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/rfc9529_trace2.json")
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
			t.Fatalf("no value %q in trace", name)
		}
		b, err := hex.DecodeString(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
}

func check(t *testing.T, name string, got []byte, err error, want []byte) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		t.Fatalf("%s = %x, want %x", name, got, want)
	}
}

func TestTranscriptHashesTrace2(t *testing.T) {
	tr := trace2(t)
	s, _ := suites.ByID(2)

	th2 := th2(s, tr("G_Y (Raw Value)"), tr("message_1 (CBOR Sequence)"))
	check(t, "TH_2", th2, nil, tr("TH_2 (Raw Value)"))

	th3 := thNext(s, th2, tr("PLAINTEXT_2 (CBOR Sequence)"), tr("CRED_R (CBOR Data Item)"))
	check(t, "TH_3", th3, nil, tr("TH_3 (Raw Value)"))

	th4 := thNext(s, th3, tr("PLAINTEXT_3 (CBOR Sequence)"), tr("CRED_I (CBOR Data Item)"))
	check(t, "TH_4", th4, nil, tr("TH_4 (Raw Value)"))
}

// TestKeyScheduleTrace2 walks through every derivation in RFC 9528, Figure 6,
// feeding each result into the next step.
func TestKeyScheduleTrace2(t *testing.T) {
	tr := trace2(t)
	s, _ := suites.ByID(2)
	th2, th3, th4 := tr("TH_2 (Raw Value)"), tr("TH_3 (Raw Value)"), tr("TH_4 (Raw Value)")

	prk2e, err := extract(s, th2, tr("G_XY (Raw Value)"))
	check(t, "PRK_2e", prk2e, err, tr("PRK_2e (Raw Value)"))

	salt3e2m, err := kdf(s, prk2e, labelSalt3e2m, th2, s.HashLength())
	check(t, "SALT_3e2m", salt3e2m, err, tr("SALT_3e2m (Raw Value)"))

	prk3e2m, err := extract(s, salt3e2m, tr("G_RX (Raw Value)"))
	check(t, "PRK_3e2m", prk3e2m, err, tr("PRK_3e2m (Raw Value)"))

	mac2, err := kdf(s, prk3e2m, labelMAC2, tr("context_2 (CBOR Sequence)"), s.MACLength)
	check(t, "MAC_2", mac2, err, tr("MAC_2 (Raw Value)"))

	plaintext2 := tr("PLAINTEXT_2 (CBOR Sequence)")
	keystream2, err := kdf(s, prk2e, labelKeystream2, th2, len(plaintext2))
	check(t, "KEYSTREAM_2", keystream2, err, tr("KEYSTREAM_2 (Raw Value)"))
	ciphertext2 := make([]byte, len(plaintext2))
	subtle.XORBytes(ciphertext2, plaintext2, keystream2)
	check(t, "CIPHERTEXT_2", ciphertext2, nil, tr("CIPHERTEXT_2 (Raw Value)"))

	k3, err := kdf(s, prk3e2m, labelK3, th3, s.KeySize)
	check(t, "K_3", k3, err, tr("K_3 (Raw Value)"))
	iv3, err := kdf(s, prk3e2m, labelIV3, th3, s.NonceSize)
	check(t, "IV_3", iv3, err, tr("IV_3 (Raw Value)"))

	salt4e3m, err := kdf(s, prk3e2m, labelSalt4e3m, th3, s.HashLength())
	check(t, "SALT_4e3m", salt4e3m, err, tr("SALT_4e3m (Raw Value)"))

	prk4e3m, err := extract(s, salt4e3m, tr("G_IY (Raw Value)"))
	check(t, "PRK_4e3m", prk4e3m, err, tr("PRK_4e3m (Raw Value)"))

	mac3, err := kdf(s, prk4e3m, labelMAC3, tr("context_3 (CBOR Sequence)"), s.MACLength)
	check(t, "MAC_3", mac3, err, tr("MAC_3 (Raw Value)"))

	prkOut, err := kdf(s, prk4e3m, labelPRKOut, th4, s.HashLength())
	check(t, "PRK_out", prkOut, err, tr("PRK_out (Raw Value)"))

	k4, err := kdf(s, prk4e3m, labelK4, th4, s.KeySize)
	check(t, "K_4", k4, err, tr("K_4 (Raw Value)"))
	iv4, err := kdf(s, prk4e3m, labelIV4, th4, s.NonceSize)
	check(t, "IV_4", iv4, err, tr("IV_4 (Raw Value)"))

	prkExporter, err := kdf(s, prkOut, labelPRKExporter, nil, s.HashLength())
	check(t, "PRK_exporter", prkExporter, err, tr("PRK_exporter (Raw Value)"))

	// EDHOC_Exporter with the OSCORE labels from RFC 9528, Appendix A.1.
	secret, err := kdf(s, prkExporter, 0, nil, 16)
	check(t, "OSCORE Master Secret", secret, err, tr("OSCORE Master Secret (Raw Value)"))
	salt, err := kdf(s, prkExporter, 1, nil, 8)
	check(t, "OSCORE Master Salt", salt, err, tr("OSCORE Master Salt (Raw Value)"))

	// EDHOC_KeyUpdate (RFC 9528, Appendix H).
	prkOut, err = kdf(s, prkOut, 11, tr("context for KeyUpdate (Raw Value)"), s.HashLength())
	check(t, "PRK_out after KeyUpdate", prkOut, err, tr("PRK_out after KeyUpdate (Raw Value)"))
	prkExporter, err = kdf(s, prkOut, labelPRKExporter, nil, s.HashLength())
	check(t, "PRK_exporter after KeyUpdate", prkExporter, err, tr("PRK_exporter after KeyUpdate (Raw Value)"))
	secret, err = kdf(s, prkExporter, 0, nil, 16)
	check(t, "OSCORE Master Secret after KeyUpdate", secret, err, tr("OSCORE Master Secret after KeyUpdate (Raw Value)"))
	salt, err = kdf(s, prkExporter, 1, nil, 8)
	check(t, "OSCORE Master Salt after KeyUpdate", salt, err, tr("OSCORE Master Salt after KeyUpdate (Raw Value)"))
}

func TestKDFRejectsOversizedOutput(t *testing.T) {
	s, _ := suites.ByID(2)
	if _, err := kdf(s, make([]byte, 32), labelKeystream2, nil, 255*32+1); err == nil {
		t.Fatal("kdf returned more than 255 hash lengths of output")
	}
}
