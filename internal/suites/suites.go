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
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	_ "crypto/sha256"
	"crypto/sha3"
	_ "crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/aquilliam/edhoc/internal/ccm"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"golang.org/x/crypto/chacha20poly1305"
)

// COSE algorithm identifiers (RFC 9053).
const (
	AlgA128GCM          = 1
	AlgA256GCM          = 3
	AlgAESCCM16_64_128  = 10
	AlgAESCCM16_128_128 = 30
	AlgChaCha20Poly1305 = 24
	AlgSHA256           = -16
	AlgSHA384           = -43
	AlgES256            = -7
	AlgES384            = -35
	AlgEdDSA            = -8
	AlgMLDSA44          = -48
)

var errInvalidPoint = errors.New("suites: invalid public key")

// A Suite is an EDHOC cipher suite.
type Suite struct {
	ID int

	// EDHOC AEAD algorithm.
	KeySize   int
	NonceSize int
	TagSize   int
	newAEAD   func(key []byte) (cipher.AEAD, error)

	// EDHOC hash algorithm: Hash for SHA-2, or SHAKE256 with a 512-bit
	// output if shake256 is set.
	Hash     crypto.Hash
	shake256 bool

	// EDHOC MAC length in bytes, used with static DH authentication.
	MACLength int

	// EDHOC key exchange algorithm. compressed is the same curve for point
	// decompression, nil for X25519, whose public keys are already in
	// compact form.
	Curve      ecdh.Curve
	compressed elliptic.Curve

	// KEM, if set, is the EDHOC key exchange algorithm instead of Curve.
	KEM kem.Scheme

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
	compressed: elliptic.P256(),
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
	compressed: elliptic.P256(),
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

var suite24 = &Suite{
	ID:         24,
	KeySize:    32,
	NonceSize:  12,
	TagSize:    16,
	newAEAD:    newAESGCM,
	Hash:       crypto.SHA384,
	MACLength:  16,
	Curve:      ecdh.P384(),
	compressed: elliptic.P384(),
	SigAlg:     AlgES384,
	AppAEAD:    AlgA256GCM,
	AppHash:    AlgSHA384,
	AppKeySize: 32,
}

var suite4 = &Suite{
	ID:         4,
	KeySize:    chacha20poly1305.KeySize,
	NonceSize:  chacha20poly1305.NonceSize,
	TagSize:    chacha20poly1305.Overhead,
	newAEAD:    chacha20poly1305.New,
	Hash:       crypto.SHA256,
	MACLength:  16,
	Curve:      ecdh.X25519(),
	SigAlg:     AlgEdDSA,
	AppAEAD:    AlgChaCha20Poly1305,
	AppHash:    AlgSHA256,
	AppKeySize: chacha20poly1305.KeySize,
}

var suite5 = &Suite{
	ID:         5,
	KeySize:    chacha20poly1305.KeySize,
	NonceSize:  chacha20poly1305.NonceSize,
	TagSize:    chacha20poly1305.Overhead,
	newAEAD:    chacha20poly1305.New,
	Hash:       crypto.SHA256,
	MACLength:  16,
	Curve:      ecdh.P256(),
	compressed: elliptic.P256(),
	SigAlg:     AlgES256,
	AppAEAD:    AlgChaCha20Poly1305,
	AppHash:    AlgSHA256,
	AppKeySize: chacha20poly1305.KeySize,
}

// suiteMinus24 is cipher suite TBD1 of draft-ietf-lake-pqsuites-02 under the
// private use label -24.
var suiteMinus24 = &Suite{
	ID:         -24,
	KeySize:    16,
	NonceSize:  13,
	TagSize:    16,
	newAEAD:    newAESCCM(16),
	shake256:   true,
	MACLength:  16,
	KEM:        mlkem512.Scheme(),
	SigAlg:     AlgMLDSA44,
	AppAEAD:    AlgAESCCM16_64_128,
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
	case 4:
		return suite4, true
	case 5:
		return suite5, true
	case 6:
		return suite6, true
	case 24:
		return suite24, true
	case -24:
		return suiteMinus24, true
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

// MaxPlaintextSize returns the longest plaintext the EDHOC AEAD algorithm
// can encrypt. AES-CCM with a 13-byte nonce encodes the length in 2 bytes.
func (s *Suite) MaxPlaintextSize() int {
	if s.NonceSize == 13 {
		return 1<<16 - 1
	}
	return math.MaxInt32
}

// AppNonceSize returns the nonce length of the application AEAD algorithm.
func (s *Suite) AppNonceSize() int {
	if s.AppAEAD == AlgAESCCM16_64_128 || s.AppAEAD == AlgAESCCM16_128_128 {
		return 13
	}
	return 12
}

// HashLength returns the output length of the EDHOC hash algorithm.
func (s *Suite) HashLength() int {
	if s.shake256 {
		return 64
	}
	return s.Hash.Size()
}

// Sum returns the EDHOC hash of the concatenation of data.
func (s *Suite) Sum(data ...[]byte) []byte {
	if s.shake256 {
		h := sha3.NewSHAKE256()
		for _, d := range data {
			h.Write(d)
		}
		out := make([]byte, 64)
		h.Read(out)
		return out
	}
	h := s.Hash.New()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// Extract is EDHOC_Extract (RFC 9528, Section 4.1.1).
func (s *Suite) Extract(salt, ikm []byte) ([]byte, error) {
	if s.shake256 {
		return kmac256(salt, ikm, 64), nil
	}
	return hkdf.Extract(s.Hash.New, ikm, salt)
}

// Expand is EDHOC_Expand (RFC 9528, Section 4.1.2).
func (s *Suite) Expand(prk, info []byte, length int) ([]byte, error) {
	if s.shake256 {
		return kmac256(prk, info, length), nil
	}
	return hkdf.Expand(s.Hash.New, prk, string(info), length)
}

// GYSize returns the length of G_Y: a public key in compact representation,
// or a KEM ciphertext.
func (s *Suite) GYSize() int {
	if s.KEM != nil {
		return s.KEM.CiphertextSize()
	}
	return s.PublicKeySize()
}

// PublicKeySize returns the length of a public key in compact representation,
// or of a KEM encapsulation key.
func (s *Suite) PublicKeySize() int {
	if s.KEM != nil {
		return s.KEM.PublicKeySize()
	}
	if s.compressed == nil {
		return 32
	}
	return (s.compressed.Params().BitSize + 7) / 8
}

// GenerateKey returns a fresh ephemeral key pair.
func (s *Suite) GenerateKey() (*ecdh.PrivateKey, error) {
	return s.Curve.GenerateKey(rand.Reader)
}

// CompactPublicKey returns the compact representation of a public key
// (RFC 9528, Appendix B): the x-coordinate alone.
func (s *Suite) CompactPublicKey(pub *ecdh.PublicKey) []byte {
	if s.compressed == nil {
		return pub.Bytes()
	}
	return pub.Bytes()[1 : 1+s.PublicKeySize()]
}

// ParsePublicKey parses a public key in compact representation. For P-256 and
// P-384 it rejects an x-coordinate that is not reduced modulo p or that is not
// on the curve. Either square root gives the same ECDH result, so the point is
// decompressed with an even y (RFC 9528, Appendix B). An X25519 key of low
// order is caught later: ECDH with it fails.
func (s *Suite) ParsePublicKey(x []byte) (*ecdh.PublicKey, error) {
	n := s.PublicKeySize()
	if len(x) != n {
		return nil, errInvalidPoint
	}
	if s.compressed == nil {
		return s.Curve.NewPublicKey(x)
	}
	px, py := elliptic.UnmarshalCompressed(s.compressed, append([]byte{2}, x...))
	if px == nil {
		return nil, errInvalidPoint
	}
	point := make([]byte, 1+2*n)
	point[0] = 4
	px.FillBytes(point[1 : 1+n])
	py.FillBytes(point[1+n:])
	return s.Curve.NewPublicKey(point)
}

// Sign signs msg with key using the EDHOC signature algorithm and returns the
// signature as COSE encodes it.
func (s *Suite) Sign(key crypto.Signer, msg []byte) ([]byte, error) {
	if s.SigAlg == AlgMLDSA44 {
		if _, ok := key.Public().(*mldsa44.PublicKey); !ok {
			return nil, errors.New("suites: ML-DSA-44 needs an ML-DSA-44 key")
		}
		return key.Sign(rand.Reader, msg, crypto.Hash(0))
	}
	if s.SigAlg == AlgEdDSA {
		if _, ok := key.Public().(ed25519.PublicKey); !ok {
			return nil, errors.New("suites: EdDSA needs an Ed25519 key")
		}
		return key.Sign(rand.Reader, msg, crypto.Hash(0))
	}
	e, ok := ecdsaAlgs[s.SigAlg]
	if !ok {
		return nil, errors.New("suites: unsupported signature algorithm")
	}
	if pub, ok := key.Public().(*ecdsa.PublicKey); !ok || pub.Curve != e.curve {
		return nil, fmt.Errorf("suites: %s needs a %s ECDSA key", e.name, e.curve.Params().Name)
	}
	h := e.hash.New()
	h.Write(msg)
	der, err := key.Sign(rand.Reader, h.Sum(nil), e.hash)
	if err != nil {
		return nil, err
	}
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) != 0 {
		return nil, errors.New("suites: signer returned a malformed ECDSA signature")
	}
	n := e.size()
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.BitLen() > 8*n || sig.S.BitLen() > 8*n {
		return nil, errors.New("suites: signer returned a malformed ECDSA signature")
	}
	out := make([]byte, 2*n)
	sig.R.FillBytes(out[:n])
	sig.S.FillBytes(out[n:])
	return out, nil
}

// Verify reports whether sig is a valid signature of msg by pub, which must be
// an ed25519.PublicKey for EdDSA, an *ecdsa.PublicKey on the right curve for
// ECDSA and an *mldsa44.PublicKey for ML-DSA-44.
func (s *Suite) Verify(pub crypto.PublicKey, msg, sig []byte) bool {
	if s.SigAlg == AlgMLDSA44 {
		k, ok := pub.(*mldsa44.PublicKey)
		return ok && mldsa44.Verify(k, msg, nil, sig)
	}
	if s.SigAlg == AlgEdDSA {
		k, ok := pub.(ed25519.PublicKey)
		return ok && len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, sig)
	}
	e, ok := ecdsaAlgs[s.SigAlg]
	if !ok {
		return false
	}
	k, ok := pub.(*ecdsa.PublicKey)
	n := e.size()
	if !ok || k.Curve != e.curve || len(sig) != 2*n {
		return false
	}
	h := e.hash.New()
	h.Write(msg)
	r := new(big.Int).SetBytes(sig[:n])
	ss := new(big.Int).SetBytes(sig[n:])
	return ecdsa.Verify(k, h.Sum(nil), r, ss)
}

// SignatureCurve returns the curve of the suite's ECDSA signature algorithm,
// or nil for EdDSA and ML-DSA.
func (s *Suite) SignatureCurve() elliptic.Curve {
	return ecdsaAlgs[s.SigAlg].curve
}

type ecdsaAlg struct {
	name  string
	curve elliptic.Curve
	hash  crypto.Hash
}

func (e ecdsaAlg) size() int {
	return (e.curve.Params().BitSize + 7) / 8
}

var ecdsaAlgs = map[int]ecdsaAlg{
	AlgES256: {"ES256", elliptic.P256(), crypto.SHA256},
	AlgES384: {"ES384", elliptic.P384(), crypto.SHA384},
}
