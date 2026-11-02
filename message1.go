package edhoc

import (
	"bytes"
	"slices"

	"github.com/aquilliam/edhoc/internal/cbor"
)

// WriteMessage1 returns message_1 (RFC 9528, Section 5.2.2), carrying ead as
// EAD_1.
func (i *Initiator) WriteMessage1(ead ...EAD) ([]byte, error) {
	if i.state != initiatorStart {
		return nil, ErrWrongState
	}
	h := &i.h
	x, err := h.ephemeral()
	if err != nil {
		return nil, i.fail(err)
	}
	b := cbor.AppendInt(nil, int64(h.cfg.Method))
	b = appendSuites(b, i.suitesI)
	b = cbor.AppendBytes(b, h.suite.CompactPublicKey(x.PublicKey()))
	b = cbor.AppendID(b, h.cI)
	b = appendEAD(b, ead)
	h.message1 = b
	i.state = initiatorWroteMessage1
	return bytes.Clone(b), nil
}

// ReadMessage1 processes message_1 (RFC 9528, Section 5.2.3). If the
// Initiator selected a cipher suite this side will not use, the error is an
// *Error with code ErrCodeWrongSelectedSuite; send ErrorMessage(err) back so
// the Initiator can try again.
func (r *Responder) ReadMessage1(msg []byte) error {
	if r.state != responderStart {
		return ErrWrongState
	}
	if err := r.readMessage1(msg); err != nil {
		return r.fail(err)
	}
	r.state = responderReadMessage1
	return nil
}

func (r *Responder) readMessage1(msg []byte) error {
	h := &r.h
	d := cbor.NewDecoder(msg)
	method, err := d.Int()
	if err != nil {
		return wrapf(err, "malformed message_1: METHOD")
	}
	suitesI, err := readSuites(d)
	if err != nil {
		return wrapf(err, "malformed message_1: SUITES_I")
	}
	gX, err := d.Bytes()
	if err != nil {
		return wrapf(err, "malformed message_1: G_X")
	}
	cI, err := d.ID()
	if err != nil {
		return wrapf(err, "malformed message_1: C_I")
	}
	ead, _, err := readEAD(d)
	if err != nil {
		return wrapf(err, "malformed message_1: EAD_1")
	}

	if Method(method) != h.cfg.Method {
		return failf("method %d is not supported", method)
	}
	// Accept only if the selected suite, the last one in SUITES_I, is the
	// first one in SUITES_I that this side supports (Section 6.3.1).
	first := slices.IndexFunc(suitesI, func(s Suite) bool {
		return slices.Contains(h.cfg.Suites, s)
	})
	if first < 0 {
		return &Error{Code: ErrCodeWrongSelectedSuite, Suites: slices.Clone(h.cfg.Suites),
			msg: "no cipher suite in SUITES_I is supported"}
	}
	if first != len(suitesI)-1 {
		return &Error{Code: ErrCodeWrongSelectedSuite, Suites: []Suite{suitesI[first]},
			msg: "a cipher suite preferred over the selected one is supported"}
	}
	h.suite, _ = suiteByID(suitesI[first])
	h.peerEph, err = h.suite.ParsePublicKey(gX)
	if err != nil {
		return wrapf(err, "invalid G_X")
	}
	if bytes.Equal(cI, h.cR) {
		return failf("C_I is the same as C_R")
	}
	h.peerEAD, err = h.acceptEAD(ead)
	if err != nil {
		return err
	}
	h.cI = bytes.Clone(cI)
	h.message1 = bytes.Clone(msg)
	return nil
}
