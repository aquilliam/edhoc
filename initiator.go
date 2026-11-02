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

// NewInitiator returns an Initiator for a new session. connID is C_I, this
// side's connection identifier. It is also this side's OSCORE Recipient ID, so
// it must differ from that of any other active session using the same OSCORE
// endpoint.
//
// The Initiator offers its most preferred suite from cfg.Suites. To start
// again after the Responder rejected that choice, pass the suites from the
// *PeerError as peerSuites; the Initiator then selects its most preferred
// suite among them. peerSuites can also be suites known in advance to be
// supported by the Responder.
func NewInitiator(cfg *Config, connID []byte, peerSuites ...Suite) (*Initiator, error) {
	if err := cfg.check(true); err != nil {
		return nil, err
	}
	i := 0
	if len(peerSuites) > 0 {
		i = slices.IndexFunc(cfg.Suites, func(s Suite) bool {
			return slices.Contains(peerSuites, s)
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
			cI:    bytes.Clone(connID),
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
		return nil, ErrWrongState
	}
	return i.session, nil
}
