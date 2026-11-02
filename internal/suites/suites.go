// Package suites holds the EDHOC cipher suites (RFC 9528, Section 3.6) and
// the algorithms behind them.
package suites

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/aquilliam/edhoc/internal/ccm"
)

// COSE algorithm identifiers (RFC 9053).
const (
	AlgAESCCM16_64_128 = 10
	AlgSHA256          = -16
	AlgES256           = -7
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

	// EDHOC key exchange algorithm.
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

// ByID returns the cipher suite with the given label, or false if it is not
// supported.
func ByID(id int) (*Suite, bool) {
	if id == 2 {
		return suite2, true
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
	return s.params.size
}

// GenerateKey returns a fresh ephemeral key pair.
func (s *Suite) GenerateKey() (*ecdh.PrivateKey, error) {
	return s.Curve.GenerateKey(rand.Reader)
}

// CompactPublicKey returns the compact representation of a public key
// (RFC 9528, Appendix B): the x-coordinate alone.
func (s *Suite) CompactPublicKey(pub *ecdh.PublicKey) []byte {
	return pub.Bytes()[1 : 1+s.params.size]
}

// ParsePublicKey parses a public key in compact representation. It rejects an
// x-coordinate that is not reduced modulo p or that is not on the curve.
func (s *Suite) ParsePublicKey(x []byte) (*ecdh.PublicKey, error) {
	return s.params.decompress(s.Curve, x)
}

// Sign signs msg with key and returns the signature as COSE encodes it.
func (s *Suite) Sign(key crypto.Signer, msg []byte) ([]byte, error) {
	if _, ok := key.Public().(*ecdsa.PublicKey); !ok {
		return nil, errors.New("suites: ES256 needs an ECDSA key")
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

// Verify reports whether sig is a valid signature of msg by pub.
func (s *Suite) Verify(pub crypto.PublicKey, msg, sig []byte) bool {
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok || len(sig) != 64 {
		return false
	}
	digest := sha256.Sum256(msg)
	r := new(big.Int).SetBytes(sig[:32])
	ss := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(k, digest[:], r, ss)
}
