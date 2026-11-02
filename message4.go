package edhoc

import (
	"github.com/aquilliam/edhoc/internal/cbor"
)

// WriteMessage4 returns message_4 (RFC 9528, Section 5.5.2), carrying ead as
// EAD_4. message_4 is optional; send it when the Responder will not send the
// Initiator any application data protected with the new keys.
func (r *Responder) WriteMessage4(ead ...EAD) ([]byte, error) {
	if r.state != responderReadMessage3 {
		return nil, ErrWrongState
	}
	h := &r.h
	ct, err := h.encrypt0(true, h.prk4e3m, labelK4, labelIV4, h.th4, appendEAD(nil, ead))
	if err != nil {
		return nil, r.fail(err)
	}
	r.state = responderWroteMessage4
	return cbor.AppendBytes(nil, ct), nil
}

// ReadMessage4 processes message_4 (RFC 9528, Section 5.5.3). Once it
// succeeds, the Initiator knows the Responder has derived the same PRK_out.
// If the Responder sent an error message instead, the error is a *PeerError.
func (i *Initiator) ReadMessage4(msg []byte) error {
	if i.state != initiatorWroteMessage3 {
		return ErrWrongState
	}
	if isErrorMessage(msg) {
		return i.fail(parseErrorMessage(msg))
	}
	h := &i.h
	ct, err := readCiphertext(msg, "message_4")
	if err != nil {
		return i.fail(err)
	}
	pt, err := h.encrypt0(false, h.prk4e3m, labelK4, labelIV4, h.th4, ct)
	if err != nil {
		return i.fail(wrapf(err, "decrypting message_4"))
	}
	ead, _, err := readEAD(cbor.NewDecoder(pt))
	if err != nil {
		return i.fail(wrapf(err, "malformed PLAINTEXT_4: EAD_4"))
	}
	if h.peerEAD, err = h.acceptEAD(ead); err != nil {
		return i.fail(err)
	}
	i.state = initiatorReadMessage4
	return nil
}
