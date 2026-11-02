package edhoc

import (
	"crypto/subtle"
	"testing"

	"github.com/aquilliam/edhoc/internal/cbor"
)

// The fuzz targets below start from the RFC 9529 trace 2 session.
// FuzzMessage1 and FuzzMessage4 take whole messages. FuzzPlaintext2 and
// FuzzPlaintext3 take a plaintext and encrypt it with the session's keys.

func FuzzMessage1(f *testing.F) {
	fs := newFuzzSetup(f)
	f.Add(fs.msg1)
	f.Add(unhex(f, "03 06 5820 741a13d7ba048fbb615e94386aa3b61bea5b3d8f65f32620b749bee8d278efa9 0e"))
	f.Fuzz(func(t *testing.T, msg []byte) {
		r, err := NewResponder(fs.cfgR, fs.cR)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.ReadMessage1(t.Context(), msg); err != nil {
			ErrorMessage(err)
			return
		}
		if _, err := r.WriteMessage2(); err != nil {
			t.Fatalf("WriteMessage2 after an accepted message_1: %v", err)
		}
	})
}

// fuzzSetup holds what the fuzz targets need from trace 2, read before
// fuzzing starts.
type fuzzSetup struct {
	cfgI, cfgR   *Config
	cI, cR       []byte
	x, y         []byte
	msg1, msg2   []byte
	gY, pt2, pt3 []byte
	msg4, errMsg []byte
}

func newFuzzSetup(f *testing.F) *fuzzSetup {
	ts := newTrace2(f)
	cfgI := *ts.cfgI
	cfgI.Suites = []Suite{Suite6, Suite2}
	return &fuzzSetup{
		cfgI:   &cfgI,
		cfgR:   ts.cfgR,
		cI:     ts.cI,
		cR:     ts.cR,
		x:      ts.tr("X (Raw Value)"),
		y:      ts.tr("Y (Raw Value)"),
		msg1:   ts.tr("message_1 (CBOR Sequence)"),
		msg2:   ts.tr("message_2 (CBOR Sequence)"),
		gY:     ts.tr("G_Y (Raw Value)"),
		pt2:    ts.tr("PLAINTEXT_2 (CBOR Sequence)"),
		pt3:    ts.tr("PLAINTEXT_3 (CBOR Sequence)"),
		msg4:   ts.tr("message_4 (CBOR Sequence)"),
		errMsg: ts.tr("error (CBOR Sequence)"),
	}
}

// initiator returns the trace 2 Initiator after message_1.
func (fs *fuzzSetup) initiator(t *testing.T) *Initiator {
	i, err := NewInitiator(fs.cfgI, fs.cI, Suite2)
	if err != nil {
		t.Fatal(err)
	}
	i.h.eph = ephemeralKey(t, fs.x)
	if _, err := i.WriteMessage1(); err != nil {
		t.Fatal(err)
	}
	return i
}

// responder returns the trace 2 Responder after message_2.
func (fs *fuzzSetup) responder(t *testing.T) *Responder {
	r, err := NewResponder(fs.cfgR, fs.cR)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadMessage1(t.Context(), fs.msg1); err != nil {
		t.Fatal(err)
	}
	r.h.eph = ephemeralKey(t, fs.y)
	if _, err := r.WriteMessage2(); err != nil {
		t.Fatal(err)
	}
	return r
}

func FuzzPlaintext2(f *testing.F) {
	fs := newFuzzSetup(f)
	f.Add(fs.pt2)
	gY := fs.gY
	f.Fuzz(func(t *testing.T, pt []byte) {
		i := fs.initiator(t)
		h := i.h
		var err error
		if h.peerEph, err = h.suite.ParsePublicKey(gY); err != nil {
			t.Fatal(err)
		}
		if err := h.derivePRK2e(gY); err != nil {
			t.Fatal(err)
		}
		keystream, err := kdf(h.suite, h.prk2e, labelKeystream2, h.th2, len(pt))
		if err != nil {
			return
		}
		body := make([]byte, len(gY)+len(pt))
		copy(body, gY)
		subtle.XORBytes(body[len(gY):], pt, keystream)
		if _, err := i.ReadMessage2(t.Context(), cbor.AppendBytes(nil, body)); err != nil {
			ErrorMessage(err)
			return
		}
		if _, err := i.WriteMessage3(); err != nil {
			t.Fatalf("WriteMessage3 after an accepted message_2: %v", err)
		}
	})
}

func FuzzPlaintext3(f *testing.F) {
	fs := newFuzzSetup(f)
	f.Add(fs.pt3)
	f.Fuzz(func(t *testing.T, pt []byte) {
		r := fs.responder(t)
		h := &r.h
		ct, err := h.encrypt0(true, h.prk3e2m, labelK3, labelIV3, h.th3, pt)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.ReadMessage3(t.Context(), cbor.AppendBytes(nil, ct)); err != nil {
			ErrorMessage(err)
			return
		}
		if _, err := r.WriteMessage4(); err != nil {
			t.Fatalf("WriteMessage4 after an accepted message_3: %v", err)
		}
	})
}

func FuzzMessage4(f *testing.F) {
	fs := newFuzzSetup(f)
	f.Add(fs.msg4)
	f.Add(fs.errMsg)
	f.Fuzz(func(t *testing.T, msg []byte) {
		i := fs.initiator(t)
		if _, err := i.ReadMessage2(t.Context(), fs.msg2); err != nil {
			t.Fatal(err)
		}
		if _, err := i.WriteMessage3(); err != nil {
			t.Fatal(err)
		}
		if _, err := i.ReadMessage4(msg); err != nil {
			ErrorMessage(err)
		}
	})
}
