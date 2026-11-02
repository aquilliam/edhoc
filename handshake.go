package edhoc

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/subtle"
	"errors"

	"github.com/aquilliam/edhoc/internal/cbor"
	"github.com/aquilliam/edhoc/internal/suites"
)

// errState is returned when a method is called out of order or after the
// session has failed.
var errState = errors.New("edhoc: method called in the wrong state")

// handshake is the protocol state shared by the Initiator and the Responder.
type handshake struct {
	cfg   *Config
	suite *suites.Suite

	eph     *ecdh.PrivateKey // X or Y
	peerEph *ecdh.PublicKey  // G_Y or G_X
	cI, cR  []byte

	message1 []byte
	th2      []byte
	th3      []byte
	th4      []byte
	prk2e    []byte
	prk3e2m  []byte
	prk4e3m  []byte
	prkOut   []byte

	peer    Credential
	peerEAD []EAD
}

// erase drops the keying material of a failed session.
func (h *handshake) erase() {
	for _, k := range [][]byte{h.prk2e, h.prk3e2m, h.prk4e3m, h.prkOut} {
		clear(k)
	}
	h.eph, h.prk2e, h.prk3e2m, h.prk4e3m, h.prkOut = nil, nil, nil, nil, nil
}

// ephemeral returns this side's ephemeral key, generating it on first use.
func (h *handshake) ephemeral() (*ecdh.PrivateKey, error) {
	if h.eph == nil {
		k, err := h.suite.GenerateKey()
		if err != nil {
			return nil, err
		}
		h.eph = k
	}
	return h.eph, nil
}

// staticKey returns this side's static DH key, checking that it is on the
// curve of the selected suite.
func (h *handshake) staticKey() (DHKey, error) {
	k := h.cfg.Key.(DHKey)
	if k.PublicKey().Curve() != h.suite.Curve {
		return nil, failf("static DH key is not on the curve of cipher suite %d", h.suite.ID)
	}
	return k, nil
}

// signer returns this side's signature key.
func (h *handshake) signer() crypto.Signer {
	return h.cfg.Key.(crypto.Signer)
}

// lookupPeer asks the application for the peer's credential and returns the
// authentication key in it: a signature key if the peer signs, otherwise a
// static DH key.
func (h *handshake) lookupPeer(id IDCred, peerSigns bool) (crypto.PublicKey, error) {
	cred, err := h.cfg.PeerCredential(id)
	if errors.Is(err, ErrUnknownCredential) {
		return nil, &Error{Code: ErrCodeUnknownCredential, msg: "looking up the peer credential", err: err}
	}
	if err != nil {
		return nil, wrapf(err, "looking up the peer credential")
	}
	if len(cred.Raw) == 0 {
		return nil, failf("peer credential is empty")
	}
	var pub crypto.PublicKey
	var ok bool
	if peerSigns {
		pub, ok = signaturePublicKey(cred.PublicKey, h.suite)
	} else {
		pub, ok = dhPublicKey(cred.PublicKey, h.suite.Curve)
	}
	if !ok {
		return nil, failf("peer credential has no key usable with method %d and cipher suite %d",
			h.cfg.Method, h.suite.ID)
	}
	h.peer = cred
	return pub, nil
}

// derivePRK2e computes TH_2 and PRK_2e (RFC 9528, Sections 4.1.1.1 and
// 5.3.2).
func (h *handshake) derivePRK2e(gY []byte) error {
	h.th2 = th2(h.suite, gY, h.message1)
	gXY, err := h.eph.ECDH(h.peerEph)
	if err != nil {
		return wrapf(err, "computing G_XY")
	}
	h.prk2e, err = extract(h.suite, h.th2, gXY)
	return err
}

// derivePRK3e2m computes PRK_3e2m from G_RX (RFC 9528, Section 4.1.1.2).
func (h *handshake) derivePRK3e2m(gRX []byte) error {
	salt, err := kdf(h.suite, h.prk2e, labelSalt3e2m, h.th2, h.suite.HashLength())
	if err != nil {
		return err
	}
	h.prk3e2m, err = extract(h.suite, salt, gRX)
	return err
}

// derivePRK4e3m computes PRK_4e3m from G_IY (RFC 9528, Section 4.1.1.3).
func (h *handshake) derivePRK4e3m(gIY []byte) error {
	salt, err := kdf(h.suite, h.prk3e2m, labelSalt4e3m, h.th3, h.suite.HashLength())
	if err != nil {
		return err
	}
	h.prk4e3m, err = extract(h.suite, salt, gIY)
	return err
}

// macLength returns the length of MAC_2 or MAC_3: the EDHOC MAC length when
// the sender uses static DH, the hash length when it signs.
func (h *handshake) macLength(signs bool) int {
	if signs {
		return h.suite.HashLength()
	}
	return h.suite.MACLength
}

// mac2 computes MAC_2 with context_2 = << C_R, ID_CRED_R, TH_2, CRED_R,
// ? EAD_2 >>.
func (h *handshake) mac2(idCredR IDCred, credR, ead []byte) ([]byte, error) {
	ctx := cbor.AppendID(nil, h.cR)
	ctx = append(ctx, idCredR.raw...)
	ctx = cbor.AppendBytes(ctx, h.th2)
	ctx = append(ctx, credR...)
	ctx = append(ctx, ead...)
	return kdf(h.suite, h.prk3e2m, labelMAC2, ctx, h.macLength(h.cfg.Method.responderSigns()))
}

// mac3 computes MAC_3 with context_3 = << ID_CRED_I, TH_3, CRED_I, ? EAD_3 >>.
func (h *handshake) mac3(idCredI IDCred, credI, ead []byte) ([]byte, error) {
	ctx := append([]byte{}, idCredI.raw...)
	ctx = cbor.AppendBytes(ctx, h.th3)
	ctx = append(ctx, credI...)
	ctx = append(ctx, ead...)
	return kdf(h.suite, h.prk4e3m, labelMAC3, ctx, h.macLength(h.cfg.Method.initiatorSigns()))
}

// toBeSigned returns the Sig_structure of the COSE_Sign1 whose signature is
// Signature_or_MAC_2 or Signature_or_MAC_3 (RFC 9528, Sections 5.3.2 and
// 5.4.2):
//
//	[ "Signature1", << ID_CRED_x >>, << TH_x, CRED_x, ? EAD_x >>, MAC_x ]
func toBeSigned(idCred IDCred, th, cred, ead, mac []byte) []byte {
	aad := cbor.AppendBytes(nil, th)
	aad = append(aad, cred...)
	aad = append(aad, ead...)
	b := cbor.AppendArray(nil, 4)
	b = cbor.AppendText(b, "Signature1")
	b = cbor.AppendBytes(b, idCred.raw)
	b = cbor.AppendBytes(b, aad)
	return cbor.AppendBytes(b, mac)
}

// macEqual compares a received MAC in constant time.
func macEqual(got, want []byte) bool {
	return subtle.ConstantTimeCompare(got, want) == 1
}

// encrypt0 seals or opens PLAINTEXT_3 or PLAINTEXT_4 as a COSE_Encrypt0 with
// an empty protected header and TH as external_aad (RFC 9528, Sections 5.4.2
// and 5.5.2).
func (h *handshake) encrypt0(seal bool, prk []byte, keyLabel, ivLabel int, th, in []byte) ([]byte, error) {
	key, err := kdf(h.suite, prk, keyLabel, th, h.suite.KeySize)
	if err != nil {
		return nil, err
	}
	iv, err := kdf(h.suite, prk, ivLabel, th, h.suite.NonceSize)
	if err != nil {
		return nil, err
	}
	aead, err := h.suite.AEAD(key)
	if err != nil {
		return nil, err
	}
	// Enc_structure = [ "Encrypt0", h'', TH ]
	aad := cbor.AppendArray(nil, 3)
	aad = cbor.AppendText(aad, "Encrypt0")
	aad = cbor.AppendBytes(aad, nil)
	aad = cbor.AppendBytes(aad, th)
	if seal {
		return aead.Seal(nil, iv, in, aad), nil
	}
	return aead.Open(nil, iv, in, aad)
}

// readCiphertext decodes message_2, message_3 or message_4: a single byte
// string.
func readCiphertext(msg []byte, name string) ([]byte, error) {
	d := cbor.NewDecoder(msg)
	ct, err := d.Bytes()
	if err != nil {
		return nil, wrapf(err, "malformed %s", name)
	}
	if !d.Done() {
		return nil, failf("malformed %s: trailing data", name)
	}
	return ct, nil
}

// finish computes PRK_out and returns the session.
func (h *handshake) finish(initiator bool) (*Session, error) {
	prkOut, err := kdf(h.suite, h.prk4e3m, labelPRKOut, h.th4, h.suite.HashLength())
	if err != nil {
		return nil, err
	}
	h.prkOut = prkOut
	s := &Session{
		suite:     h.suite,
		initiator: initiator,
		cI:        h.cI,
		cR:        h.cR,
		peer:      h.peer,
	}
	if err := s.setPRKOut(bytes.Clone(prkOut)); err != nil {
		return nil, err
	}
	return s, nil
}
