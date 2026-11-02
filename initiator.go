package edhoc

import (
	"bytes"
	"errors"
	"slices"
)

type initiatorState int

const (
	initiatorStart initiatorState = iota
	initiatorWroteMessage1
	initiatorReadMessage2
	initiatorWroteMessage3
	initiatorReadMessage4
	initiatorFailed
)

// An Initiator runs the Initiator side of one EDHOC session. Call
// WriteMessage1, ReadMessage2, WriteMessage3 and, if the application uses
// it, ReadMessage4, in that order. After any error the session is over and
// every later call fails.
//
// An Initiator is not safe for concurrent use.
type Initiator struct {
	h       handshake
	suitesI []Suite
	state   initiatorState
	session *Session
}

// NewInitiator returns an Initiator for a new session.
func NewInitiator(cfg *Config) (*Initiator, error) {
	if err := cfg.check(true); err != nil {
		return nil, err
	}
	i := 0
	if len(cfg.PeerSuites) > 0 {
		i = slices.IndexFunc(cfg.Suites, func(s Suite) bool {
			return slices.Contains(cfg.PeerSuites, s)
		})
		if i < 0 {
			return nil, errors.New("edhoc: no cipher suite in common with the Responder")
		}
	}
	suite, _ := suiteByID(cfg.Suites[i])
	return &Initiator{
		h: handshake{
			cfg:   cfg,
			suite: suite,
			cI:    bytes.Clone(cfg.ConnID),
		},
		suitesI: slices.Clone(cfg.Suites[:i+1]),
	}, nil
}

// fail ends the session.
func (i *Initiator) fail(err error) error {
	i.state = initiatorFailed
	i.h.erase()
	return err
}

// PeerCredential returns the Responder's credential once ReadMessage2 has
// succeeded.
func (i *Initiator) PeerCredential() Credential {
	return i.h.peer
}

// PeerEAD returns the EAD items in the last message read, without padding.
func (i *Initiator) PeerEAD() []EAD {
	return i.h.peerEAD
}

// Session returns the session once WriteMessage3 has succeeded.
func (i *Initiator) Session() (*Session, error) {
	if i.session == nil || i.state == initiatorFailed {
		return nil, errState
	}
	return i.session, nil
}
