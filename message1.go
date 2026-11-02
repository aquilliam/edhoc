package edhoc

import (
	"bytes"
	"context"
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

// ReadMessage1 processes message_1 (RFC 9528, Section 5.2.3) and returns
// what it carries. If Config.GetConfig is set, it is called with ctx. If the
// Initiator selected a cipher suite this side will not use, the error is an
// *Error with code ErrCodeWrongSelectedSuite; send ErrorMessage(err) back so
// the Initiator can try again.
func (r *Responder) ReadMessage1(ctx context.Context, msg []byte) (*Message1Info, error) {
	if r.state != responderStart {
		return nil, ErrWrongState
	}
	m, err := r.readMessage1(ctx, msg)
	if err != nil {
		return nil, r.fail(err)
	}
	r.state = responderReadMessage1
	return m, nil
}

func (r *Responder) readMessage1(ctx context.Context, msg []byte) (*Message1Info, error) {
	h := &r.h
	d := cbor.NewDecoder(msg)
	method, err := d.Int()
	if err != nil {
		return nil, wrapf(err, "malformed message_1: METHOD")
	}
	suitesI, err := readSuites(d)
	if err != nil {
		return nil, wrapf(err, "malformed message_1: SUITES_I")
	}
	gX, err := d.Bytes()
	if err != nil {
		return nil, wrapf(err, "malformed message_1: G_X")
	}
	cI, err := d.ID()
	if err != nil {
		return nil, wrapf(err, "malformed message_1: C_I")
	}
	ead, _, err := readEAD(d)
	if err != nil {
		return nil, wrapf(err, "malformed message_1: EAD_1")
	}

	get := h.cfg.GetConfig
	if method < int64(MethodSignSign) || method > int64(MethodStaticStatic) ||
		get == nil && Method(method) != h.cfg.Method {
		return nil, failf("method %d is not supported", method)
	}
	// Accept only if the selected suite, the last one in SUITES_I, is the
	// first one in SUITES_I that this side supports (Section 6.3.1).
	first := slices.IndexFunc(suitesI, func(s Suite) bool {
		return slices.Contains(h.cfg.Suites, s)
	})
	if first < 0 {
		return nil, &Error{Code: ErrCodeWrongSelectedSuite, Suites: slices.Clone(h.cfg.Suites),
			Info: "no cipher suite in SUITES_I is supported"}
	}
	if first != len(suitesI)-1 {
		return nil, &Error{Code: ErrCodeWrongSelectedSuite, Suites: []Suite{suitesI[first]},
			Info: "a cipher suite preferred over the selected one is supported"}
	}
	h.suite, _ = suiteByID(suitesI[first])
	h.peerEph, err = h.suite.ParsePublicKey(gX)
	if err != nil {
		return nil, wrapf(err, "invalid G_X")
	}

	m := &Message1Info{
		Method:     Method(method),
		Suite:      suitesI[first],
		Suites:     slices.Clone(suitesI),
		EAD:        slices.DeleteFunc(slices.Clone(ead), func(e EAD) bool { return e.Label == 0 }),
		PeerConnID: bytes.Clone(cI),
	}
	if get != nil {
		cfg, err := get(ctx, m)
		if err != nil {
			return nil, wrapf(err, "no configuration for this message_1")
		}
		if cfg == nil {
			return nil, failf("no configuration for this message_1")
		}
		if err := cfg.check(false); err != nil {
			return nil, wrapf(err, "no configuration for this message_1")
		}
		if cfg.Method != m.Method {
			return nil, failf("method %d is not supported", method)
		}
		if !slices.Contains(cfg.Suites, m.Suite) {
			return nil, failf("configuration does not include the selected cipher suite")
		}
		h.cfg = cfg
	}
	if m.EAD, err = h.acceptEAD(ead); err != nil {
		return nil, err
	}
	h.cI = bytes.Clone(cI)
	h.message1 = bytes.Clone(msg)
	return m, nil
}
