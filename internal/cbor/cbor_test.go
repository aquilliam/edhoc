package cbor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Examples from RFC 8949, Appendix A.
func TestAppendInt(t *testing.T) {
	tests := []struct {
		v    int64
		want string
	}{
		{0, "00"},
		{1, "01"},
		{10, "0a"},
		{23, "17"},
		{24, "1818"},
		{25, "1819"},
		{100, "1864"},
		{1000, "1903e8"},
		{1000000, "1a000f4240"},
		{1000000000000, "1b000000e8d4a51000"},
		{math.MaxInt64, "1b7fffffffffffffff"},
		{-1, "20"},
		{-10, "29"},
		{-24, "37"},
		{-25, "3818"},
		{-100, "3863"},
		{-1000, "3903e7"},
		{math.MinInt64, "3b7fffffffffffffff"},
	}
	for _, tt := range tests {
		got := AppendInt(nil, tt.v)
		if hex.EncodeToString(got) != tt.want {
			t.Errorf("AppendInt(%d) = %x, want %s", tt.v, got, tt.want)
		}
		v, err := NewDecoder(got).Int()
		if err != nil || v != tt.v {
			t.Errorf("Int(%x) = %d, %v, want %d", got, v, err, tt.v)
		}
	}
	if got := AppendUint(nil, math.MaxUint64); hex.EncodeToString(got) != "1bffffffffffffffff" {
		t.Errorf("AppendUint(MaxUint64) = %x", got)
	}
}

func TestAppendStrings(t *testing.T) {
	tests := []struct {
		got  []byte
		want string
	}{
		{AppendBytes(nil, nil), "40"},
		{AppendBytes(nil, []byte{1, 2, 3, 4}), "4401020304"},
		{AppendBytes(nil, make([]byte, 24)), "5818" + hex.EncodeToString(make([]byte, 24))},
		{AppendText(nil, ""), "60"},
		{AppendText(nil, "a"), "6161"},
		{AppendText(nil, "IETF"), "6449455446"},
		{AppendText(nil, "ü"), "62c3bc"},
		{AppendArray(nil, 0), "80"},
		{AppendArray(nil, 3), "83"},
		{AppendArray(nil, 25), "9819"},
		{AppendMap(nil, 0), "a0"},
		{AppendMap(nil, 2), "a2"},
	}
	for _, tt := range tests {
		if hex.EncodeToString(tt.got) != tt.want {
			t.Errorf("got %x, want %s", tt.got, tt.want)
		}
	}
}

func TestDecoderSequence(t *testing.T) {
	// message_1 from RFC 9529, Section 3.3.
	d := NewDecoder(unhex(t, "038206025820"+
		"8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6"+"37"))
	method, err := d.Int()
	if err != nil || method != 3 {
		t.Fatalf("METHOD = %d, %v", method, err)
	}
	if m, _ := d.Major(); m != majorArray {
		t.Fatalf("SUITES_I major type = %d, want array", m)
	}
	n, err := d.Array()
	if err != nil || n != 2 {
		t.Fatalf("SUITES_I length = %d, %v", n, err)
	}
	for _, want := range []int64{6, 2} {
		if s, err := d.Int(); err != nil || s != want {
			t.Fatalf("suite = %d, %v, want %d", s, err, want)
		}
	}
	gx, err := d.Bytes()
	if err != nil || len(gx) != 32 {
		t.Fatalf("G_X = %x, %v", gx, err)
	}
	cI, err := d.ID()
	if err != nil || !bytes.Equal(cI, []byte{0x37}) {
		t.Fatalf("C_I = %x, %v", cI, err)
	}
	if !d.Done() {
		t.Fatalf("trailing data %x", d.Rest())
	}
}

func TestDecoderTypeMismatchDoesNotAdvance(t *testing.T) {
	d := NewDecoder(unhex(t, "4401020304"))
	if _, err := d.Int(); !errors.Is(err, ErrType) {
		t.Fatalf("Int() error = %v, want ErrType", err)
	}
	if _, err := d.Text(); !errors.Is(err, ErrType) {
		t.Fatalf("Text() error = %v, want ErrType", err)
	}
	if v, err := d.Bytes(); err != nil || len(v) != 4 {
		t.Fatalf("Bytes() = %x, %v", v, err)
	}
}

func TestDecoderErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		read func(*Decoder) error
		want error
	}{
		{"empty", "", readInt, ErrMalformed},
		{"truncated argument", "19 01", readInt, ErrMalformed},
		{"one-byte argument below 24", "18 17", readInt, ErrNotDeterministic},
		{"two-byte argument fits in one", "19 00 ff", readInt, ErrNotDeterministic},
		{"four-byte argument fits in two", "1a 00 00 ff ff", readInt, ErrNotDeterministic},
		{"eight-byte argument fits in four", "1b 00 00 00 00 ff ff ff ff", readInt, ErrNotDeterministic},
		{"reserved additional information", "1c", readInt, ErrMalformed},
		{"indefinite-length integer", "1f", readInt, ErrMalformed},
		{"negative integer below int64", "3b 80 00 00 00 00 00 00 00", readInt, ErrUnsupported},
		{"byte string longer than input", "45 01 02", readBytes, ErrMalformed},
		{"indefinite-length byte string", "5f 41 01 ff", readBytes, ErrNotDeterministic},
		{"invalid UTF-8", "61 ff", readText, ErrMalformed},
		{"array longer than input", "83 01", readArray, ErrMalformed},
		{"indefinite-length array", "9f 06 02 ff", readArray, ErrNotDeterministic},
		{"identifier as one-byte byte string", "41 0e", readID, ErrNotDeterministic},
		{"identifier as text", "61 61", readID, ErrType},
		{"map with keys out of order", "a2 03 04 01 02", readRaw, ErrNotDeterministic},
		{"map with repeated key", "a2 01 02 01 03", readRaw, ErrMalformed},
		{"map with longer key first", "a2 1818 00 17 00", readRaw, ErrNotDeterministic},
		{"half-precision float", "f9 7c 00", readRaw, ErrUnsupported},
		{"unassigned simple value", "f0", readRaw, ErrUnsupported},
		{"break outside indefinite item", "ff", readRaw, ErrMalformed},
		{"nested too deeply", "818181818181818181818181818181818180", readRaw, ErrUnsupported},
		{"truncated array element", "82 01", readRaw, ErrMalformed},
		{"truncated map value", "a1 01", readRaw, ErrMalformed},
		{"invalid UTF-8 inside array", "81 61 ff", readRaw, ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDecoder(unhex(t, removeSpaces(tt.in)))
			err := tt.read(d)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if d.off != 0 {
				t.Fatalf("decoder advanced to %d after an error", d.off)
			}
		})
	}
}

func TestRaw(t *testing.T) {
	tests := []string{
		"00",
		"3bffffffffffffffff",
		"40",
		"6449455446",
		"83010203",
		"a201020304",
		"f4", "f5", "f6", "f7",
		"c11a514b67b0",
		// ID_CRED_R and CRED_R from RFC 9529, Section 3.4.
		"a1044132",
		"a2026b6578616d706c652e65647508a101a501020241322001215820bbc3496052" +
			"6ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e2" +
			"57236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072",
		// Keys sort by encoding, so 10 comes before -1 (0x20).
		"a20a002000",
	}
	for _, in := range tests {
		data := unhex(t, in)
		d := NewDecoder(append(data, 0x01))
		got, err := d.Raw()
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("Raw(%s) = %x, %v", in, got, err)
		}
		if v, err := d.Int(); err != nil || v != 1 {
			t.Errorf("Raw(%s) consumed the wrong number of bytes", in)
		}
	}
}

func TestID(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"0e", "0e"},
		{"37", "37"},
		{"27", "27"},
		{"00", "00"},
		{"17", "17"},
		{"20", "20"},
		{"18", "4118"},
		{"38", "4138"},
		{"ff", "41ff"},
		{"abcd", "42abcd"},
		{"", "40"},
	}
	for _, tt := range tests {
		id := unhex(t, tt.id)
		got := AppendID(nil, id)
		if hex.EncodeToString(got) != tt.want {
			t.Errorf("AppendID(%s) = %x, want %s", tt.id, got, tt.want)
		}
		back, err := NewDecoder(got).ID()
		if err != nil || !bytes.Equal(back, id) {
			t.Errorf("ID(%x) = %x, %v, want %s", got, back, err, tt.id)
		}
	}
}

func FuzzRaw(f *testing.F) {
	f.Add([]byte{0x83, 0x01, 0x02, 0x03})
	f.Add([]byte{0xa2, 0x01, 0x02, 0x03, 0x04})
	f.Add([]byte{0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0})
	f.Fuzz(func(t *testing.T, data []byte) {
		item, err := NewDecoder(data).Raw()
		if err != nil {
			return
		}
		if !bytes.HasPrefix(data, item) {
			t.Fatalf("Raw returned %x, which is not a prefix of the input", item)
		}
		d := NewDecoder(item)
		again, err := d.Raw()
		if err != nil || !bytes.Equal(again, item) || !d.Done() {
			t.Fatalf("decoding %x a second time gave %x, %v", item, again, err)
		}
	})
}

func FuzzID(f *testing.F) {
	f.Add([]byte{0x37})
	f.Add([]byte{0x18})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, id []byte) {
		enc := AppendID(nil, id)
		d := NewDecoder(enc)
		got, err := d.ID()
		if err != nil || !bytes.Equal(got, id) || !d.Done() {
			t.Fatalf("ID(AppendID(%x)) = %x, %v", id, got, err)
		}
	})
}

func readInt(d *Decoder) error   { _, err := d.Int(); return err }
func readBytes(d *Decoder) error { _, err := d.Bytes(); return err }
func readText(d *Decoder) error  { _, err := d.Text(); return err }
func readArray(d *Decoder) error { _, err := d.Array(); return err }
func readID(d *Decoder) error    { _, err := d.ID(); return err }
func readRaw(d *Decoder) error   { _, err := d.Raw(); return err }

func removeSpaces(s string) string {
	return string(bytes.ReplaceAll([]byte(s), []byte(" "), nil))
}
