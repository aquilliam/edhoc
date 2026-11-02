package edhoc

import (
	"bytes"
	"testing"
)

func TestCoAPRequest(t *testing.T) {
	msg := []byte{0x58, 0x02, 0xaa, 0xbb}
	cR, got, first, err := ParseCoAPRequest(CoAPMessage1(msg))
	if err != nil || !first || cR != nil || !bytes.Equal(got, msg) {
		t.Errorf("message_1: cR %x, msg %x, message1 %v, err %v", cR, got, first, err)
	}
	for _, id := range [][]byte{{0x27}, {0x18}, {}, {1, 2, 3}} {
		cR, got, first, err := ParseCoAPRequest(CoAPRequest(id, msg))
		if err != nil || first || !bytes.Equal(cR, id) || !bytes.Equal(got, msg) {
			t.Errorf("C_R %x: cR %x, msg %x, message1 %v, err %v", id, cR, got, first, err)
		}
	}
	if !bytes.Equal(CoAPRequest([]byte{0x27}, msg)[:1], []byte{0x27}) {
		t.Error("one-byte C_R not encoded as an integer")
	}
	for _, bad := range [][]byte{nil, {0x41, 0x05}, {0x43, 0x01}} {
		if _, _, _, err := ParseCoAPRequest(bad); err == nil {
			t.Errorf("ParseCoAPRequest(%x) succeeded", bad)
		}
	}
}
