// Package suites holds the EDHOC cipher suites (RFC 9528, Section 3.6) and
// the algorithms behind them.
package suites

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/aquilliam/edhoc/internal/ccm"
)

// COSE algorithm identifiers (RFC 9053).
const (
	AlgA128GCM          = 1
	AlgAESCCM16_64_128  = 10
	AlgAESCCM16_128_128 = 30
	AlgSHA256           = -16
	AlgES256            = -7
	AlgEdDSA            = -8
)

// A Suite is an EDHOC cipher suite.
type Suite struct {
	ID int

	// EDHOC AEAD algorithm.
	KeySize   int
	NonceSize int
	TagSize   int
	newAEAD   func(key []byte) (cipher.AEAD, error)

	// EDHOC hash algorithm.
	Hash crypto.Hash

	// EDHOC MAC length in bytes, used with static DH authentication.
	MACLength int

	// EDHOC key exchange algorithm. params is nil for X25519, whose public
	// keys are already in compact form.
	Curve  ecdh.Curve
	params *curve

	// EDHOC signature algorithm.
	SigAlg int

	// Application AEAD and hash algorithms, as COSE identifiers, and the key
	// length of the application AEAD algorithm.
	AppAEAD    int
	AppHash    int
	AppKeySize int
}

var suite0 = &Suite{
	ID:         0,
	KeySize:    16,
	NonceSize:  13,
	TagSize:    8,
	newAEAD:    newAESCCM(8),
	Hash:       crypto.SHA256,
	MACLength:  8,
	Curve:      ecdh.X25519(),
	SigAlg:     AlgEdDSA,
	AppAEAD:    AlgAESCCM16_64_128,
	AppHash:    AlgSHA256,
	AppKeySize: 16,
}

var suite2 = &Suite{
	ID:         2,
	KeySize:    16,
	NonceSize:  13,
	TagSize:    8,
	newAEAD:    newAESCCM(8),
	Hash:       crypto.SHA256,
	MACLength:  8,
	Curve:      ecdh.P256(),
	params:     p256,
	SigAlg:     AlgES256,
	AppAEAD:    AlgAESCCM16_64_128,
	AppHash:    AlgSHA256,
	AppKeySize: 16,
}

var suite1 = &Suite{
	ID:         1,
	KeySize:    16,
	NonceSize:  13,
	TagSize:    16,
	newAEAD:    newAESCCM(16),
	Hash:       crypto.SHA256,
	MACLength:  16,
	Curve:      ecdh.X25519(),
	SigAlg:     AlgEdDSA,
	AppAEAD:    AlgAESCCM16_64_128,
	AppHash:    AlgSHA256,
	AppKeySize: 16,
}

var suite3 = &Suite{
	ID:         3,
	KeySize:    16,
	NonceSize:  13,
	TagSize:    16,
	newAEAD:    newAESCCM(16),
	Hash:       crypto.SHA256,
	MACLength:  16,
	Curve:      ecdh.P256(),
	params:     p256,
	SigAlg:     AlgES256,
	AppAEAD:    AlgAESCCM16_64_128,
	AppHash:    AlgSHA256,
	AppKeySize: 16,
}

var suite6 = &Suite{
	ID:         6,
	KeySize:    16,
	NonceSize:  12,
	TagSize:    16,
	newAEAD:    newAESGCM,
	Hash:       crypto.SHA256,
	MACLength:  16,
	Curve:      ecdh.X25519(),
	SigAlg:     AlgES256,
	AppAEAD:    AlgA128GCM,
	AppHash:    AlgSHA256,
	AppKeySize: 16,
}

// ByID returns the cipher suite with the given label, or false if it is not
// supported.
func ByID(id int) (*Suite, bool) {
	switch id {
	case 0:
		return suite0, true
	case 1:
		return suite1, true
	case 2:
		return suite2, true
	case 3:
		return suite3, true
	case 6:
		return suite6, true
	}
	return nil, false
}

func newAESCCM(tagSize int) func([]byte) (cipher.AEAD, error) {
	return func(key []byte) (cipher.AEAD, error) {
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return ccm.New(b, tagSize, 13)
	}
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// AEAD returns the EDHOC AEAD algorithm keyed with key.
func (s *Suite) AEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != s.KeySize {
		return nil, errors.New("suites: wrong AEAD key length")
	}
	return s.newAEAD(key)
}

// HashLength returns the output length of the EDHOC hash algorithm.
func (s *Suite) HashLength() int {
	return s.Hash.Size()
}

// PublicKeySize returns the length of a public key in compact representation.
func (s *Suite) PublicKeySize() int {
	if s.params == nil {
		return 32
	}
	return s.params.size
}

// GenerateKey returns a fresh ephemeral key pair.
func (s *Suite) GenerateKey() (*ecdh.PrivateKey, error) {
	return s.Curve.GenerateKey(rand.Reader)
}

// CompactPublicKey returns the compact representation of a public key
// (RFC 9528, Appendix B): the x-coordinate alone.
func (s *Suite) CompactPublicKey(pub *ecdh.PublicKey) []byte {
	if s.params == nil {
		return pub.Bytes()
	}
	return pub.Bytes()[1 : 1+s.params.size]
}

// ParsePublicKey parses a public key in compact representation. For P-256 it
// rejects an x-coordinate that is not reduced modulo p or that is not on the
// curve. An X25519 key of low order is caught later: ECDH with it fails.
func (s *Suite) ParsePublicKey(x []byte) (*ecdh.PublicKey, error) {
	if s.params == nil {
		if len(x) != 32 {
			return nil, errInvalidPoint
		}
		return s.Curve.NewPublicKey(x)
	}
	return s.params.decompress(s.Curve, x)
}

// Sign signs msg with key using the EDHOC signature algorithm and returns the
// signature as COSE encodes it.
func (s *Suite) Sign(key crypto.Signer, msg []byte) ([]byte, error) {
	switch s.SigAlg {
	case AlgEdDSA:
		if _, ok := key.Public().(ed25519.PublicKey); !ok {
			return nil, errors.New("suites: EdDSA needs an Ed25519 key")
		}
		return key.Sign(rand.Reader, msg, crypto.Hash(0))
	case AlgES256:
		return signES256(key, msg)
	}
	return nil, errors.New("suites: unsupported signature algorithm")
}

// Verify reports whether sig is a valid signature of msg by pub, which must be
// an ed25519.PublicKey for EdDSA and an *ecdsa.PublicKey for ES256.
func (s *Suite) Verify(pub crypto.PublicKey, msg, sig []byte) bool {
	switch s.SigAlg {
	case AlgEdDSA:
		k, ok := pub.(ed25519.PublicKey)
		return ok && len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, sig)
	case AlgES256:
		return verifyES256(pub, msg, sig)
	}
	return false
}

func signES256(key crypto.Signer, msg []byte) ([]byte, error) {
	if pub, ok := key.Public().(*ecdsa.PublicKey); !ok || pub.Curve.Params().Name != "P-256" {
		return nil, errors.New("suites: ES256 needs a P-256 ECDSA key")
	}
	digest := sha256.Sum256(msg)
	der, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) != 0 {
		return nil, errors.New("suites: signer returned a malformed ECDSA signature")
	}
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.BitLen() > 256 || sig.S.BitLen() > 256 {
		return nil, errors.New("suites: signer returned a malformed ECDSA signature")
	}
	out := make([]byte, 64)
	sig.R.FillBytes(out[:32])
	sig.S.FillBytes(out[32:])
	return out, nil
}

func verifyES256(pub crypto.PublicKey, msg, sig []byte) bool {
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok || k.Curve.Params().Name != "P-256" || len(sig) != 64 {
		return false
	}
	digest := sha256.Sum256(msg)
	r := new(big.Int).SetBytes(sig[:32])
	ss := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(k, digest[:], r, ss)
}
