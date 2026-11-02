package edhoc

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"slices"

	"github.com/aquilliam/edhoc/internal/suites"
)

// A Method is an EDHOC authentication method (RFC 9528, Section 3.2). It says
// whether each side authenticates with a signature key or a static
// Diffie-Hellman key.
type Method int

const (
	MethodSignSign     Method = 0 // Initiator signs, Responder signs
	MethodSignStatic   Method = 1 // Initiator signs, Responder uses static DH
	MethodStaticSign   Method = 2 // Initiator uses static DH, Responder signs
	MethodStaticStatic Method = 3 // both use static DH
)

// A Suite is an EDHOC cipher suite (RFC 9528, Section 3.6).
type Suite int

// Suite2 is AES-CCM-16-64-128, SHA-256, 8-byte MAC, P-256, ES256, with
// AES-CCM-16-64-128 and SHA-256 as the application algorithms.
const Suite2 Suite = 2

// A DHKey is a static Diffie-Hellman private key. *ecdh.PrivateKey satisfies
// it; so can a key held in hardware.
type DHKey interface {
	PublicKey() *ecdh.PublicKey
	ECDH(remote *ecdh.PublicKey) ([]byte, error)
}

// An EAD is an external authorization data item (RFC 9528, Section 3.8). A
// negative Label marks the item as critical. Value is nil when the item has
// no ead_value.
type EAD struct {
	Label int
	Value []byte
}

// Config configures one side of an EDHOC session. A Config may be shared by
// several sessions but must not be changed once it has been passed to
// NewInitiator or NewResponder.
type Config struct {
	// Method is the authentication method. Only MethodStaticStatic is
	// implemented so far.
	Method Method

	// Suites lists the supported cipher suites. For the Initiator the order
	// is its order of preference, most preferred first.
	Suites []Suite

	// PeerSuites is SUITES_R from an error message the Responder sent in
	// reply to an earlier message_1. The Initiator then selects its most
	// preferred suite among them. Responders ignore it.
	PeerSuites []Suite

	// ConnID is this side's connection identifier: C_I for the Initiator,
	// C_R for the Responder. It is also this side's OSCORE Recipient ID, so
	// a session fails if both sides pick the same one.
	ConnID []byte

	// Credential is this side's authentication credential, CRED_I or CRED_R.
	Credential Credential

	// Key is the private authentication key matching Credential. For static
	// DH authentication it must be a DHKey.
	Key any

	// PeerCredential looks up the peer's credential from the ID_CRED field
	// it sent. It is called during ReadMessage2 on the Initiator and
	// ReadMessage3 on the Responder, before the peer has been authenticated,
	// so it must not treat the identifier as proof of anything. Return an
	// error wrapping ErrUnknownCredential if there is no such credential.
	PeerCredential func(id IDCred) (Credential, error)

	// EADLabels lists the absolute values of the EAD labels the application
	// handles. A received critical EAD item with any other label fails the
	// session. Padding (label 0) is always discarded.
	EADLabels []int
}

// suiteByID returns the implementation of a suite.
func suiteByID(id Suite) (*suites.Suite, bool) {
	return suites.ByID(int(id))
}

// check validates the parts of a Config that both roles use.
func (c *Config) check() error {
	if c.Method != MethodStaticStatic {
		return fmt.Errorf("edhoc: method %d is not supported", c.Method)
	}
	if len(c.Suites) == 0 {
		return errors.New("edhoc: no cipher suites configured")
	}
	for i, s := range c.Suites {
		if _, ok := suiteByID(s); !ok {
			return fmt.Errorf("edhoc: cipher suite %d is not supported", s)
		}
		if slices.Contains(c.Suites[:i], s) {
			return fmt.Errorf("edhoc: cipher suite %d is listed twice", s)
		}
	}
	if len(c.Credential.Raw) == 0 {
		return errors.New("edhoc: Credential.Raw is empty")
	}
	if c.Credential.ID.raw == nil {
		return errors.New("edhoc: Credential.ID is not set")
	}
	key, ok := c.Key.(DHKey)
	if !ok {
		return errors.New("edhoc: static DH authentication needs a Key that implements DHKey")
	}
	if pub, ok := c.Credential.PublicKey.(*ecdh.PublicKey); ok && !pub.Equal(key.PublicKey()) {
		return errors.New("edhoc: Key does not match the public key in Credential")
	}
	if c.PeerCredential == nil {
		return errors.New("edhoc: PeerCredential is not set")
	}
	return nil
}
