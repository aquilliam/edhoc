package edhoc

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
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

func (m Method) String() string {
	switch m {
	case MethodSignSign:
		return "sign-sign"
	case MethodSignStatic:
		return "sign-static"
	case MethodStaticSign:
		return "static-sign"
	case MethodStaticStatic:
		return "static-static"
	}
	return fmt.Sprintf("method %d", int(m))
}

func (m Method) initiatorSigns() bool { return m == MethodSignSign || m == MethodSignStatic }
func (m Method) responderSigns() bool { return m == MethodSignSign || m == MethodStaticSign }

// A Suite is an EDHOC cipher suite (RFC 9528, Section 3.6).
type Suite int

// The cipher suites this package implements, from RFC 9528, Section 10.2. The
// comment after each lists the EDHOC AEAD and hash algorithms, the MAC length
// for static DH authentication, and the key exchange and signature
// algorithms. Suites 0 to 3 use AES-CCM-16-64-128 and SHA-256 for the
// application; the others use their own EDHOC AEAD and hash.
const (
	Suite0  Suite = 0  // AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA
	Suite1  Suite = 1  // AES-CCM-16-128-128, SHA-256, 16, X25519, EdDSA
	Suite2  Suite = 2  // AES-CCM-16-64-128, SHA-256, 8, P-256, ES256
	Suite3  Suite = 3  // AES-CCM-16-128-128, SHA-256, 16, P-256, ES256
	Suite4  Suite = 4  // ChaCha20/Poly1305, SHA-256, 16, X25519, EdDSA
	Suite5  Suite = 5  // ChaCha20/Poly1305, SHA-256, 16, P-256, ES256
	Suite6  Suite = 6  // A128GCM, SHA-256, 16, X25519, ES256
	Suite24 Suite = 24 // A256GCM, SHA-384, 16, P-384, ES384
)

var suiteNames = map[Suite]string{
	Suite0:  "AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA",
	Suite1:  "AES-CCM-16-128-128, SHA-256, 16, X25519, EdDSA",
	Suite2:  "AES-CCM-16-64-128, SHA-256, 8, P-256, ES256",
	Suite3:  "AES-CCM-16-128-128, SHA-256, 16, P-256, ES256",
	Suite4:  "ChaCha20/Poly1305, SHA-256, 16, X25519, EdDSA",
	Suite5:  "ChaCha20/Poly1305, SHA-256, 16, P-256, ES256",
	Suite6:  "A128GCM, SHA-256, 16, X25519, ES256",
	Suite24: "A256GCM, SHA-384, 16, P-384, ES384",
}

// String returns the suite's label and, for a suite this package implements,
// its algorithms, such as "suite 2 (AES-CCM-16-64-128, SHA-256, 8, P-256,
// ES256)".
func (s Suite) String() string {
	if name, ok := suiteNames[s]; ok {
		return fmt.Sprintf("suite %d (%s)", int(s), name)
	}
	return fmt.Sprintf("suite %d", int(s))
}

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

// PeerInfo is what Config.PeerCredential is told about the peer and the
// session.
type PeerInfo struct {
	// ID is the ID_CRED field the peer sent: ID_CRED_R in message_2 or
	// ID_CRED_I in message_3.
	ID IDCred

	// EAD holds the EAD items sent in the same message, without padding.
	EAD []EAD

	// ConnID is this side's connection identifier and PeerConnID the peer's.
	ConnID, PeerConnID []byte
}

// Config configures one side of EDHOC sessions. A Config may be shared by
// any number of sessions but must not be changed once it has been passed to
// NewInitiator or NewResponder. Values that differ between sessions, such as
// the connection identifier, are passed to NewInitiator and NewResponder.
type Config struct {
	// Method is the authentication method. Both sides must use the same one.
	Method Method

	// Suites lists the supported cipher suites. For the Initiator the order
	// is its order of preference, most preferred first.
	Suites []Suite

	// Credential is this side's authentication credential, CRED_I or CRED_R.
	Credential Credential

	// Key is the private authentication key matching Credential: a
	// crypto.Signer if this side authenticates with a signature, a DHKey if
	// it uses static DH. Signing keys are ed25519.PrivateKey for EdDSA and
	// *ecdsa.PrivateKey on P-256 for ES256 or on P-384 for ES384, or anything
	// else that implements crypto.Signer with those public keys, such as a key
	// in a KMS. Static DH keys must be on the curve of the selected suite.
	Key any

	// PeerCredential returns the peer's credential for the ID_CRED field it
	// sent, or an error wrapping ErrUnknownCredential if there is no such
	// credential. It is called during ReadMessage2 on the Initiator and
	// ReadMessage3 on the Responder, with the context passed to them, before
	// the peer has been authenticated, so nothing in p is proof of anything.
	// The returned credential is the one the peer must then prove it holds
	// the key for.
	PeerCredential func(ctx context.Context, p *PeerInfo) (Credential, error)

	// EADLabels lists the absolute values of the EAD labels the application
	// handles. A received critical EAD item with any other label fails the
	// session. Padding (label 0) is always discarded.
	EADLabels []int
}

// suiteByID returns the implementation of a suite.
func suiteByID(id Suite) (*suites.Suite, bool) {
	return suites.ByID(int(id))
}

// check validates a Config for one role.
func (c *Config) check(initiator bool) error {
	if c.Method < MethodSignSign || c.Method > MethodStaticStatic {
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
	if c.Credential.ID.raw == "" {
		return errors.New("edhoc: Credential.ID is not set")
	}
	signs := c.Method.initiatorSigns()
	if !initiator {
		signs = c.Method.responderSigns()
	}
	pub := c.signerOrDHPublic(signs)
	if pub == nil && signs {
		return errors.New("edhoc: signature authentication needs a Key that implements crypto.Signer")
	}
	if pub == nil {
		return errors.New("edhoc: static DH authentication needs a Key that implements DHKey")
	}
	if c.Credential.PublicKey != nil && !samePublicKey(pub, c.Credential.PublicKey) {
		return errors.New("edhoc: Key does not match the public key in Credential")
	}
	if c.PeerCredential == nil {
		return errors.New("edhoc: PeerCredential is not set")
	}
	return nil
}

// signerOrDHPublic returns the public half of Key, or nil if Key is not of the
// kind the method needs.
func (c *Config) signerOrDHPublic(signs bool) crypto.PublicKey {
	if signs {
		if k, ok := c.Key.(crypto.Signer); ok {
			return k.Public()
		}
		return nil
	}
	if k, ok := c.Key.(DHKey); ok {
		return k.PublicKey()
	}
	return nil
}

// dhPublicKey returns pub as an ECDH public key on curve.
func dhPublicKey(pub crypto.PublicKey, curve ecdh.Curve) (*ecdh.PublicKey, bool) {
	switch k := pub.(type) {
	case *ecdh.PublicKey:
		return k, k.Curve() == curve
	case *ecdsa.PublicKey:
		e, err := k.ECDH()
		return e, err == nil && e.Curve() == curve
	}
	return nil, false
}

// signaturePublicKey returns pub in the form the suite's signature algorithm
// verifies with.
func signaturePublicKey(pub crypto.PublicKey, s *suites.Suite) (crypto.PublicKey, bool) {
	if s.SigAlg == suites.AlgEdDSA {
		k, ok := pub.(ed25519.PublicKey)
		return k, ok && len(k) == ed25519.PublicKeySize
	}
	curve := s.SignatureCurve()
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return k, k.Curve == curve
	case *ecdh.PublicKey:
		e, err := ecdsa.ParseUncompressedPublicKey(curve, k.Bytes())
		return e, err == nil
	}
	return nil, false
}

// samePublicKey reports whether a and b are the same key. A NIST curve key may
// be given as *ecdsa.PublicKey or *ecdh.PublicKey.
func samePublicKey(a, b crypto.PublicKey) bool {
	if ea, ok := a.(*ecdsa.PublicKey); ok {
		if e, err := ea.ECDH(); err == nil {
			a = e
		}
	}
	if eb, ok := b.(*ecdsa.PublicKey); ok {
		if e, err := eb.ECDH(); err == nil {
			b = e
		}
	}
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}
