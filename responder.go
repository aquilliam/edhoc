package edhoc

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

// NewResponder returns a Responder for a new session. Its connection
// identifier is chosen later, in WriteMessage2.
func NewResponder(cfg *Config) (*Responder, error) {
	err := cfg.checkSuites()
	if cfg.GetConfig == nil {
		err = cfg.check(false)
	}
	if err != nil {
		return nil, err
	}
	return &Responder{h: handshake{cfg: cfg}}, nil
}

func (r *Responder) fail(err error) error {
	r.state = responderFailed
	r.h.erase()
	return err
}

// Session returns the session once ReadMessage3 has succeeded.
func (r *Responder) Session() (*Session, error) {
	if r.session == nil || r.state == responderFailed {
		return nil, ErrWrongState
	}
	return r.session, nil
}
