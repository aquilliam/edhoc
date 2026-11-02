package edhoc

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"unicode/utf8"

	"github.com/aquilliam/edhoc/internal/cbor"
)

// COSE header parameter and key labels (RFC 9052, Sections 3.1 and 7.1).
const (
	headerKID     = 4
	headerKCCS    = 14
	headerX5Chain = 33
	headerX5T     = 34

	algSHA256_64 = -15

	keyKty     = 1
	keyKID     = 2
	keyCrv     = -1
	keyX       = -2
	keyY       = -3
	ktyOKP     = 1
	ktyEC2     = 2
	crvP256    = 1
	crvP384    = 2
	crvX25519  = 4
	crvEd25519 = 6

	claimSub   = 2
	claimCnf   = 8
	cnfCOSEKey = 1
)

// An IDCred is an ID_CRED field (RFC 9528, Section 3.5.3): a COSE header map
// that identifies a credential, such as { 4 : kid }.
type IDCred struct {
	raw []byte
}

// KeyID returns the ID_CRED { 4 : kid }.
func KeyID(kid []byte) IDCred {
	b := cbor.AppendMap(nil, 1)
	b = cbor.AppendInt(b, headerKID)
	b = cbor.AppendBytes(b, kid)
	return IDCred{raw: b}
}

// X5T returns the ID_CRED { 34 : [-15, hash] } that identifies a DER-encoded
// X.509 certificate by the first 8 bytes of its SHA-256 hash (RFC 9360).
func X5T(der []byte) IDCred {
	h := sha256.Sum256(der)
	b := cbor.AppendMap(nil, 1)
	b = cbor.AppendInt(b, headerX5T)
	b = cbor.AppendArray(b, 2)
	b = cbor.AppendInt(b, algSHA256_64)
	b = cbor.AppendBytes(b, h[:8])
	return IDCred{raw: b}
}

// X5Chain returns the ID_CRED { 33 : x5chain } that carries an X.509
// certificate chain by value (RFC 9360). certs are DER-encoded, starting with
// the end-entity certificate. It panics if certs is empty.
func X5Chain(certs ...[]byte) IDCred {
	if len(certs) == 0 {
		panic("edhoc: X5Chain needs at least one certificate")
	}
	b := cbor.AppendMap(nil, 1)
	b = cbor.AppendInt(b, headerX5Chain)
	if len(certs) == 1 {
		b = cbor.AppendBytes(b, certs[0])
		return IDCred{raw: b}
	}
	b = cbor.AppendArray(b, len(certs))
	for _, c := range certs {
		b = cbor.AppendBytes(b, c)
	}
	return IDCred{raw: b}
}

// KCCS returns the ID_CRED { 14 : ccs } that carries an encoded CWT Claims Set
// by value (RFC 9528, Section 3.5.3).
func KCCS(ccs []byte) IDCred {
	b := cbor.AppendMap(nil, 1)
	b = cbor.AppendInt(b, headerKCCS)
	b = append(b, ccs...)
	return IDCred{raw: b}
}

// ParseIDCred returns the IDCred for an encoded COSE header map, for ID_CRED
// forms this package has no constructor for.
func ParseIDCred(raw []byte) (IDCred, error) {
	d := cbor.NewDecoder(raw)
	m, err := d.RawHeaderMap()
	if err != nil || !d.Done() {
		return IDCred{}, errors.New("edhoc: ID_CRED is not a single COSE header map")
	}
	return IDCred{raw: bytes.Clone(m)}, nil
}

// Bytes returns the encoded header map.
func (id IDCred) Bytes() []byte {
	return bytes.Clone(id.raw)
}

// Equal reports whether id and other have the same encoding.
func (id IDCred) Equal(other IDCred) bool {
	return bytes.Equal(id.raw, other.raw)
}

// KeyID returns the kid if the header map is exactly { 4 : kid }.
func (id IDCred) KeyID() ([]byte, bool) {
	d, ok := id.single(headerKID)
	if !ok {
		return nil, false
	}
	kid, err := d.Bytes()
	if err != nil || !d.Done() {
		return nil, false
	}
	return bytes.Clone(kid), true
}

// X5Chain returns the DER-encoded certificates if the header map is exactly
// { 33 : x5chain }. The certificates are not parsed or verified.
func (id IDCred) X5Chain() ([][]byte, bool) {
	d, ok := id.single(headerX5Chain)
	if !ok {
		return nil, false
	}
	if m, _ := d.Major(); m == 2 {
		c, err := d.Bytes()
		if err != nil || !d.Done() {
			return nil, false
		}
		return [][]byte{bytes.Clone(c)}, true
	}
	n, err := d.Array()
	if err != nil || n == 0 {
		return nil, false
	}
	certs := make([][]byte, 0, n)
	for range n {
		c, err := d.Bytes()
		if err != nil {
			return nil, false
		}
		certs = append(certs, bytes.Clone(c))
	}
	return certs, d.Done()
}

// KCCS returns the encoded CWT Claims Set if the header map is exactly
// { 14 : ccs }. The result can be passed to ParseCCS.
func (id IDCred) KCCS() ([]byte, bool) {
	d, ok := id.single(headerKCCS)
	if !ok {
		return nil, false
	}
	if m, _ := d.Major(); m != 5 {
		return nil, false
	}
	ccs, err := d.Raw()
	if err != nil || !d.Done() {
		return nil, false
	}
	return bytes.Clone(ccs), true
}

// single returns a decoder positioned at the value if the header map has
// exactly one entry, with the given label.
func (id IDCred) single(label int64) (*cbor.Decoder, bool) {
	d := cbor.NewDecoder(id.raw)
	if n, err := d.Map(); err != nil || n != 1 {
		return nil, false
	}
	if l, err := d.Int(); err != nil || l != label {
		return nil, false
	}
	return d, true
}

// appendCompact appends the ID_CRED field as it appears in PLAINTEXT_2 and
// PLAINTEXT_3: just the kid when the map holds a single kid (RFC 9528,
// Section 3.5.3.2), otherwise the map.
func (id IDCred) appendCompact(b []byte) []byte {
	if kid, ok := id.KeyID(); ok {
		return cbor.AppendID(b, kid)
	}
	return append(b, id.raw...)
}

// readIDCred reads an ID_CRED field from a plaintext.
func readIDCred(d *cbor.Decoder) (IDCred, error) {
	if m, _ := d.Major(); m == 5 {
		raw, err := d.RawHeaderMap()
		if err != nil {
			return IDCred{}, err
		}
		id := IDCred{raw: bytes.Clone(raw)}
		if _, ok := id.KeyID(); ok {
			return IDCred{}, cbor.ErrNotDeterministic
		}
		return id, nil
	}
	kid, err := d.ID()
	if err != nil {
		return IDCred{}, err
	}
	return KeyID(kid), nil
}

// A Credential is an authentication credential, CRED_I or CRED_R (RFC 9528,
// Section 3.5.2).
type Credential struct {
	// ID identifies the credential in EDHOC messages.
	ID IDCred

	// Raw is the credential exactly as both sides use it in the transcript,
	// for example the encoded CWT Claims Set of a raw public key.
	Raw []byte

	// PublicKey is the authentication key in the credential. For static DH
	// authentication it is an *ecdh.PublicKey.
	PublicKey crypto.PublicKey
}

// NewX509 returns the credential for a DER-encoded X.509 certificate,
// identified by X5T. To send the certificate by value instead, set ID to
// X5Chain(der, intermediates...). CRED is the certificate as a CBOR byte string (RFC 9528,
// Section 3.5.2). The certificate is parsed for its public key but not
// verified; that is up to the application.
func NewX509(der []byte) (Credential, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Credential{}, err
	}
	return Credential{
		ID:        X5T(der),
		Raw:       cbor.AppendBytes(nil, der),
		PublicKey: cert.PublicKey,
	}, nil
}

var errCCS = errors.New("edhoc: malformed CWT Claims Set")

// ParseCCS returns the credential for a CWT Claims Set holding a COSE_Key in
// a 'cnf' claim, the way EDHOC carries raw public keys. If the COSE_Key has a
// kid, the credential's ID is { 4 : kid }; otherwise the caller sets ID. To
// send the claims set by value, set ID to KCCS(ccs).
//
// Supported keys are P-256 and P-384 (EC2 with both coordinates), X25519 and
// Ed25519. P-256, P-384 and X25519 keys come back as *ecdh.PublicKey, Ed25519
// keys as ed25519.PublicKey.
func ParseCCS(ccs []byte) (Credential, error) {
	d := cbor.NewDecoder(ccs)
	if _, err := cbor.NewDecoder(ccs).Raw(); err != nil {
		return Credential{}, errCCS
	}
	var key []byte
	err := readMap(d, func(label int64, d *cbor.Decoder) error {
		if label != claimCnf {
			_, err := d.Raw()
			return err
		}
		return readMap(d, func(label int64, d *cbor.Decoder) error {
			var err error
			if label == cnfCOSEKey {
				key, err = d.Raw()
			} else {
				_, err = d.Raw()
			}
			return err
		})
	})
	if err != nil || !d.Done() || key == nil {
		return Credential{}, errCCS
	}
	pub, kid, err := parseCOSEKey(key)
	if err != nil {
		return Credential{}, err
	}
	cred := Credential{Raw: bytes.Clone(ccs), PublicKey: pub}
	if kid != nil {
		cred.ID = KeyID(kid)
	}
	return cred, nil
}

// NewCCS returns a credential for a raw public key: a CWT Claims Set with an
// optional subject claim and a COSE_Key in a 'cnf' claim (RFC 9528, Section
// 3.5.2). The credential's ID is { 4 : kid }. pub may be a P-256 or P-384 key
// (*ecdh.PublicKey or *ecdsa.PublicKey), an X25519 key (*ecdh.PublicKey) or
// an ed25519.PublicKey.
func NewCCS(subject string, kid []byte, pub crypto.PublicKey) (Credential, error) {
	if !utf8.ValidString(subject) {
		return Credential{}, errors.New("edhoc: subject is not valid UTF-8")
	}
	key, err := appendCOSEKey(nil, kid, pub)
	if err != nil {
		return Credential{}, err
	}
	var b []byte
	if subject != "" {
		b = cbor.AppendMap(b, 2)
		b = cbor.AppendInt(b, claimSub)
		b = cbor.AppendText(b, subject)
	} else {
		b = cbor.AppendMap(b, 1)
	}
	b = cbor.AppendInt(b, claimCnf)
	b = cbor.AppendMap(b, 1)
	b = cbor.AppendInt(b, cnfCOSEKey)
	b = append(b, key...)
	return Credential{ID: KeyID(kid), Raw: b, PublicKey: pub}, nil
}

// appendCOSEKey appends a COSE_Key with deterministically ordered labels.
func appendCOSEKey(b, kid []byte, pub crypto.PublicKey) ([]byte, error) {
	if k, ok := pub.(*ecdsa.PublicKey); ok {
		e, err := k.ECDH()
		if err != nil {
			return nil, err
		}
		pub = e
	}
	var kty, crv int64
	var x, y []byte
	switch k := pub.(type) {
	case *ecdh.PublicKey:
		switch k.Curve() {
		case ecdh.P256():
			p := k.Bytes()
			kty, crv, x, y = ktyEC2, crvP256, p[1:33], p[33:]
		case ecdh.P384():
			p := k.Bytes()
			kty, crv, x, y = ktyEC2, crvP384, p[1:49], p[49:]
		case ecdh.X25519():
			kty, crv, x = ktyOKP, crvX25519, k.Bytes()
		default:
			return nil, errors.New("edhoc: unsupported curve for a COSE_Key")
		}
	case ed25519.PublicKey:
		kty, crv, x = ktyOKP, crvEd25519, k
	default:
		return nil, errors.New("edhoc: unsupported public key type for a COSE_Key")
	}
	n := 4
	if y != nil {
		n = 5
	}
	b = cbor.AppendMap(b, n)
	b = cbor.AppendInt(b, keyKty)
	b = cbor.AppendInt(b, kty)
	b = cbor.AppendInt(b, keyKID)
	b = cbor.AppendBytes(b, kid)
	b = cbor.AppendInt(b, keyCrv)
	b = cbor.AppendInt(b, crv)
	b = cbor.AppendInt(b, keyX)
	b = cbor.AppendBytes(b, x)
	if y != nil {
		b = cbor.AppendInt(b, keyY)
		b = cbor.AppendBytes(b, y)
	}
	return b, nil
}

// parseCOSEKey returns the public key and kid of a COSE_Key.
func parseCOSEKey(b []byte) (crypto.PublicKey, []byte, error) {
	var kty, crv int64
	var kid, x, y []byte
	err := readMap(cbor.NewDecoder(b), func(label int64, d *cbor.Decoder) error {
		var err error
		switch label {
		case keyKty:
			kty, err = d.Int()
		case keyKID:
			kid, err = d.Bytes()
		case keyCrv:
			crv, err = d.Int()
		case keyX:
			x, err = d.Bytes()
		case keyY:
			y, err = d.Bytes()
		default:
			_, err = d.Raw()
		}
		return err
	})
	if err != nil {
		return nil, nil, errCCS
	}
	var pub crypto.PublicKey
	switch {
	case kty == ktyEC2 && crv == crvP256 && len(x) == 32 && len(y) == 32:
		pub, err = ecdh.P256().NewPublicKey(append(append([]byte{4}, x...), y...))
	case kty == ktyEC2 && crv == crvP384 && len(x) == 48 && len(y) == 48:
		pub, err = ecdh.P384().NewPublicKey(append(append([]byte{4}, x...), y...))
	case kty == ktyOKP && crv == crvX25519 && len(x) == 32 && y == nil:
		pub, err = ecdh.X25519().NewPublicKey(x)
	case kty == ktyOKP && crv == crvEd25519 && len(x) == ed25519.PublicKeySize && y == nil:
		pub = ed25519.PublicKey(bytes.Clone(x))
	default:
		return nil, nil, errors.New("edhoc: unsupported COSE_Key")
	}
	if err != nil {
		return nil, nil, errors.New("edhoc: COSE_Key holds an invalid public key")
	}
	return pub, bytes.Clone(kid), nil
}

// readMap reads a map with integer keys and calls f to read each value.
// Entries with other keys are skipped.
func readMap(d *cbor.Decoder, f func(label int64, d *cbor.Decoder) error) error {
	n, err := d.Map()
	if err != nil {
		return err
	}
	for range n {
		label, err := d.Int()
		if err != nil {
			if _, err := d.Raw(); err != nil {
				return err
			}
			if _, err := d.Raw(); err != nil {
				return err
			}
			continue
		}
		if err := f(label, d); err != nil {
			return err
		}
	}
	return nil
}
