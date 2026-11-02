package edhoc

import "bytes"

type responderState int

const (
	responderStart responderState = iota
	responderReadMessage1
	responderWroteMessage2
	responderReadMessage3
	responderWroteMessage4
	responderFailed
)

// A Responder runs the Responder side of one EDHOC session. Call
// ReadMessage1, WriteMessage2, ReadMessage3 and, if the application uses it,
// WriteMessage4, in that order. After any error the session is over and every
// later call fails.
//
// A Responder keeps state between message_1 and message_3. A server that
// accepts sessions from untrusted peers should limit how many it keeps (RFC
// 9528, Section 9.7).
//
// A Responder is not safe for concurrent use.
type Responder struct {
	h       handshake
	state   responderState
	session *Session
}

// NewResponder returns a Responder for a new session. connID is C_R, this
// side's connection identifier. The Initiator puts C_R in front of message_3
// when EDHOC runs over CoAP, so a server uses it to find the Responder for a
// message_3. It is also this side's OSCORE Recipient ID. Either way it must
// differ from that of any other active session.
func NewResponder(cfg *Config, connID []byte) (*Responder, error) {
	if err := cfg.check(false); err != nil {
		return nil, err
	}
	return &Responder{h: handshake{cfg: cfg, cR: bytes.Clone(connID)}}, nil
}

func (r *Responder) fail(err error) error {
	r.state = responderFailed
	r.h.erase()
	return err
}

// PeerCredential returns the Initiator's credential once ReadMessage3 has
// succeeded.
func (r *Responder) PeerCredential() Credential {
	return r.h.peer
}

// PeerEAD returns the EAD items in the last message read, without padding.
func (r *Responder) PeerEAD() []EAD {
	return r.h.peerEAD
}

// Session returns the session once ReadMessage3 has succeeded.
func (r *Responder) Session() (*Session, error) {
	if r.session == nil || r.state == responderFailed {
		return nil, ErrWrongState
	}
	return r.session, nil
}
