package edhoc

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"errors"
	"unicode/utf8"

	"github.com/aquilliam/edhoc/internal/cbor"
)

// COSE header parameter and key labels (RFC 9052, Sections 3.1 and 7.1).
const (
	headerKID = 4

	keyKty  = 1
	keyKID  = 2
	keyCrv  = -1
	keyX    = -2
	keyY    = -3
	ktyEC2  = 2
	crvP256 = 1

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
	d := cbor.NewDecoder(id.raw)
	if n, err := d.Map(); err != nil || n != 1 {
		return nil, false
	}
	if label, err := d.Int(); err != nil || label != headerKID {
		return nil, false
	}
	kid, err := d.Bytes()
	if err != nil || !d.Done() {
		return nil, false
	}
	return bytes.Clone(kid), true
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

var errCCS = errors.New("edhoc: malformed CWT Claims Set")

// ParseCCS returns the credential for a CWT Claims Set holding a COSE_Key in
// a 'cnf' claim, the way EDHOC carries raw public keys. If the COSE_Key has a
// kid, the credential's ID is { 4 : kid }; otherwise the caller sets ID.
//
// Only EC2 keys on P-256 with both coordinates are supported so far.
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
// 3.5.2). The credential's ID is { 4 : kid }. Only P-256 keys are supported so
// far.
func NewCCS(subject string, kid []byte, pub *ecdh.PublicKey) (Credential, error) {
	if pub.Curve() != ecdh.P256() {
		return Credential{}, errors.New("edhoc: NewCCS supports only P-256 keys")
	}
	if !utf8.ValidString(subject) {
		return Credential{}, errors.New("edhoc: subject is not valid UTF-8")
	}
	point := pub.Bytes()
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
	b = cbor.AppendMap(b, 5)
	b = cbor.AppendInt(b, keyKty)
	b = cbor.AppendInt(b, ktyEC2)
	b = cbor.AppendInt(b, keyKID)
	b = cbor.AppendBytes(b, kid)
	b = cbor.AppendInt(b, keyCrv)
	b = cbor.AppendInt(b, crvP256)
	b = cbor.AppendInt(b, keyX)
	b = cbor.AppendBytes(b, point[1:33])
	b = cbor.AppendInt(b, keyY)
	b = cbor.AppendBytes(b, point[33:])
	return Credential{ID: KeyID(kid), Raw: b, PublicKey: pub}, nil
}

// parseCOSEKey returns the public key and kid of a COSE_Key.
func parseCOSEKey(b []byte) (*ecdh.PublicKey, []byte, error) {
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
	if kty != ktyEC2 || crv != crvP256 || len(x) != 32 || len(y) != 32 {
		return nil, nil, errors.New("edhoc: COSE_Key is not a P-256 EC2 key with x and y")
	}
	point := append(append([]byte{4}, x...), y...)
	pub, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		return nil, nil, errors.New("edhoc: COSE_Key is not a valid P-256 point")
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
