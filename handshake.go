package edhoc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/subtle"
	"errors"

	"github.com/aquilliam/edhoc/internal/cbor"
	"github.com/aquilliam/edhoc/internal/suites"
	"github.com/cloudflare/circl/kem"
)

// handshake is the protocol state shared by the Initiator and the Responder.
type handshake struct {
	cfg   *Config
	suite *suites.Suite

	eph     *ecdh.PrivateKey // X or Y
	peerEph *ecdh.PublicKey  // G_Y or G_X

	// For a KEM suite, the Initiator's decapsulation key and the
	// encapsulation key in G_X.
	kemKey  kem.PrivateKey
	kemPeer kem.PublicKey
	cI, cR  []byte

	message1 []byte
	th2      []byte
	th3      []byte
	th4      []byte
	prk2e    []byte
	prk3e2m  []byte
	prk4e3m  []byte

	peer Credential
}

// erase drops all keying material, once the session has failed or message_4
// has been sent or received.
func (h *handshake) erase() {
	for _, k := range [][]byte{h.prk2e, h.prk3e2m, h.prk4e3m} {
		clear(k)
	}
	h.eph, h.kemKey, h.prk2e, h.prk3e2m, h.prk4e3m = nil, nil, nil, nil, nil
}

// eraseBeforeMessage4 drops the keying material that message_4 does not need.
// PRK_3e2m and PRK_2e may share memory with PRK_4e3m, which is kept.
func (h *handshake) eraseBeforeMessage4() {
	for _, k := range [][]byte{h.prk2e, h.prk3e2m} {
		if len(k) > 0 && len(h.prk4e3m) > 0 && &k[0] == &h.prk4e3m[0] {
			continue
		}
		clear(k)
	}
	h.eph, h.kemKey, h.prk2e, h.prk3e2m = nil, nil, nil, nil
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

// writeGX returns G_X: the compact ephemeral public key, or a fresh
// encapsulation key for a KEM suite (draft-ietf-lake-pqsuites, Section 3).
func (h *handshake) writeGX() ([]byte, error) {
	if h.suite.KEM != nil {
		pk, sk, err := h.suite.KEM.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		h.kemKey = sk
		return pk.MarshalBinary()
	}
	x, err := h.ephemeral()
	if err != nil {
		return nil, err
	}
	return h.suite.CompactPublicKey(x.PublicKey()), nil
}

// readGX parses G_X from message_1.
func (h *handshake) readGX(gX []byte) error {
	var err error
	if h.suite.KEM != nil {
		h.kemPeer, err = h.suite.KEM.UnmarshalBinaryPublicKey(gX)
	} else {
		h.peerEph, err = h.suite.ParsePublicKey(gX)
	}
	return err
}

// writeGY returns G_Y and G_XY: the compact ephemeral public key and the ECDH
// shared secret, or the ciphertext and shared secret of an encapsulation to
// G_X for a KEM suite.
func (h *handshake) writeGY() (gY, gXY []byte, err error) {
	if h.suite.KEM != nil {
		return h.suite.KEM.Encapsulate(h.kemPeer)
	}
	y, err := h.ephemeral()
	if err != nil {
		return nil, nil, err
	}
	gXY, err = y.ECDH(h.peerEph)
	if err != nil {
		return nil, nil, wrapf(err, "computing G_XY")
	}
	return h.suite.CompactPublicKey(y.PublicKey()), gXY, nil
}

// readGY parses G_Y from message_2 and returns G_XY.
func (h *handshake) readGY(gY []byte) ([]byte, error) {
	if h.suite.KEM != nil {
		gXY, err := h.suite.KEM.Decapsulate(h.kemKey, gY)
		if err != nil {
			return nil, wrapf(err, "invalid G_Y")
		}
		return gXY, nil
	}
	var err error
	h.peerEph, err = h.suite.ParsePublicKey(gY)
	if err != nil {
		return nil, wrapf(err, "invalid G_Y")
	}
	gXY, err := h.eph.ECDH(h.peerEph)
	if err != nil {
		return nil, wrapf(err, "computing G_XY")
	}
	return gXY, nil
}

// staticKey returns this side's static DH key. Config.check has made sure it
// is on the curve of every configured suite.
func (h *handshake) staticKey() DHKey {
	return h.cfg.Key.(DHKey)
}

// signer returns this side's signature key.
func (h *handshake) signer() crypto.Signer {
	return h.cfg.Key.(crypto.Signer)
}

// lookupPeer asks the application for the peer's credential and returns the
// authentication key in it: a signature key if the peer signs, otherwise a
// static DH key.
func (h *handshake) lookupPeer(ctx context.Context, id IDCred, ead []EAD, ownConnID, peerConnID []byte, peerSigns bool) (crypto.PublicKey, error) {
	cred, err := h.cfg.PeerCredential(ctx, &PeerInfo{
		ID:         id,
		EAD:        ead,
		ConnID:     bytes.Clone(ownConnID),
		PeerConnID: bytes.Clone(peerConnID),
	})
	if errors.Is(err, ErrUnknownCredential) {
		return nil, &Error{Code: ErrCodeUnknownCredential, Info: "looking up the peer credential", err: err}
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
func (h *handshake) derivePRK2e(gY, gXY []byte) error {
	h.th2 = th2(h.suite, gY, h.message1)
	var err error
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
	ctx := []byte(idCredI.raw)
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
	b = cbor.AppendBytes(b, []byte(idCred.raw))
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
	if seal && len(in) > h.suite.MaxPlaintextSize() {
		return nil, failf("plaintext is too long for the EDHOC AEAD algorithm")
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
	s := &Session{
		suite:     h.suite,
		initiator: initiator,
		cI:        h.cI,
		cR:        h.cR,
		peer:      h.peer,
	}
	if err := s.setPRKOut(prkOut); err != nil {
		clear(prkOut)
		return nil, err
	}
	h.eraseBeforeMessage4()
	return s, nil
}
