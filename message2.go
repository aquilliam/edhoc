package edhoc

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/subtle"
	"errors"

	"github.com/aquilliam/edhoc/internal/cbor"
)

// WriteMessage2 returns message_2 (RFC 9528, Section 5.3.2), carrying ead as
// EAD_2. connID is C_R, this side's connection identifier. It must differ
// from C_I, Message1Info.PeerConnID; if it does not, WriteMessage2 returns an
// error and can be called again with another connID. It is also this side's
// OSCORE Recipient ID, and over CoAP the Initiator puts it in front of
// message_3 so that a server can find the Responder, so it must differ from
// that of any other active session.
func (r *Responder) WriteMessage2(connID []byte, ead ...EAD) ([]byte, error) {
	if r.state != responderReadMessage1 {
		return nil, ErrWrongState
	}
	if bytes.Equal(connID, r.h.cI) {
		return nil, errors.New("edhoc: C_R must differ from C_I")
	}
	r.h.cR = bytes.Clone(connID)
	msg, err := r.writeMessage2(ead)
	if err != nil {
		return nil, r.fail(err)
	}
	r.state = responderWroteMessage2
	return msg, nil
}

func (r *Responder) writeMessage2(ead []EAD) ([]byte, error) {
	h := &r.h
	y, err := h.ephemeral()
	if err != nil {
		return nil, err
	}
	gY := h.suite.CompactPublicKey(y.PublicKey())
	if err := h.derivePRK2e(gY); err != nil {
		return nil, err
	}
	signs := h.cfg.Method.responderSigns()
	if signs {
		h.prk3e2m = h.prk2e
	} else {
		key := h.staticKey()
		gRX, err := key.ECDH(h.peerEph)
		if err != nil {
			return nil, wrapf(err, "computing G_RX")
		}
		if err := h.derivePRK3e2m(gRX); err != nil {
			return nil, err
		}
	}

	cred := &h.cfg.Credential
	eadRaw := appendEAD(nil, ead)
	mac2, err := h.mac2(cred.ID, cred.Raw, eadRaw)
	if err != nil {
		return nil, err
	}
	sigOrMAC := mac2
	if signs {
		sigOrMAC, err = h.suite.Sign(h.signer(), toBeSigned(cred.ID, h.th2, cred.Raw, eadRaw, mac2))
		if err != nil {
			return nil, wrapf(err, "signing message_2")
		}
	}
	// PLAINTEXT_2 = ( C_R, ID_CRED_R / bstr / -24..23, Signature_or_MAC_2, ? EAD_2 )
	pt := cbor.AppendID(nil, h.cR)
	pt = cred.ID.appendCompact(pt)
	pt = cbor.AppendBytes(pt, sigOrMAC)
	pt = append(pt, eadRaw...)

	keystream, err := kdf(h.suite, h.prk2e, labelKeystream2, h.th2, len(pt))
	if err != nil {
		return nil, wrapf(err, "PLAINTEXT_2 is too long")
	}
	// G_Y_CIPHERTEXT_2 = G_Y || (PLAINTEXT_2 XOR KEYSTREAM_2)
	body := make([]byte, len(gY)+len(pt))
	copy(body, gY)
	subtle.XORBytes(body[len(gY):], pt, keystream)

	h.th3 = thNext(h.suite, h.th2, pt, cred.Raw)
	return cbor.AppendBytes(nil, body), nil
}

// ReadMessage2 processes message_2 (RFC 9528, Section 5.3.3) and returns its
// EAD items, without padding. It calls Config.PeerCredential with ctx to find
// the Responder's credential and checks the Responder's proof of possession
// of the key in it. If the Responder sent an error message instead, the error
// is a *PeerError.
func (i *Initiator) ReadMessage2(ctx context.Context, msg []byte) ([]EAD, error) {
	if i.state != initiatorWroteMessage1 {
		return nil, ErrWrongState
	}
	if isErrorMessage(msg) {
		return nil, i.fail(parseErrorMessage(msg))
	}
	ead, err := i.readMessage2(ctx, msg)
	if err != nil {
		return nil, i.fail(err)
	}
	i.state = initiatorReadMessage2
	return ead, nil
}

func (i *Initiator) readMessage2(ctx context.Context, msg []byte) ([]EAD, error) {
	h := &i.h
	body, err := readCiphertext(msg, "message_2")
	if err != nil {
		return nil, err
	}
	n := h.suite.PublicKeySize()
	if len(body) <= n {
		return nil, failf("malformed message_2: too short")
	}
	gY, ct := body[:n], body[n:]
	h.peerEph, err = h.suite.ParsePublicKey(gY)
	if err != nil {
		return nil, wrapf(err, "invalid G_Y")
	}
	if err := h.derivePRK2e(gY); err != nil {
		return nil, err
	}
	keystream, err := kdf(h.suite, h.prk2e, labelKeystream2, h.th2, len(ct))
	if err != nil {
		return nil, wrapf(err, "CIPHERTEXT_2 is too long")
	}
	pt := make([]byte, len(ct))
	subtle.XORBytes(pt, ct, keystream)

	d := cbor.NewDecoder(pt)
	cR, err := d.ID()
	if err != nil {
		return nil, wrapf(err, "malformed PLAINTEXT_2: C_R")
	}
	idCredR, err := readIDCred(d)
	if err != nil {
		return nil, wrapf(err, "malformed PLAINTEXT_2: ID_CRED_R")
	}
	sigOrMAC, err := d.Bytes()
	if err != nil {
		return nil, wrapf(err, "malformed PLAINTEXT_2: Signature_or_MAC_2")
	}
	ead, eadRaw, err := readEAD(d)
	if err != nil {
		return nil, wrapf(err, "malformed PLAINTEXT_2: EAD_2")
	}
	if bytes.Equal(cR, h.cI) {
		return nil, failf("C_R is the same as C_I")
	}
	h.cR = bytes.Clone(cR)

	signs := h.cfg.Method.responderSigns()
	accepted, err := h.acceptEAD(ead)
	if err != nil {
		return nil, err
	}
	peerKey, err := h.lookupPeer(ctx, idCredR, accepted, h.cI, h.cR, signs)
	if err != nil {
		return nil, err
	}
	if signs {
		h.prk3e2m = h.prk2e
	} else {
		x, _ := h.ephemeral()
		gRX, err := x.ECDH(peerKey.(*ecdh.PublicKey))
		if err != nil {
			return nil, wrapf(err, "computing G_RX")
		}
		if err := h.derivePRK3e2m(gRX); err != nil {
			return nil, err
		}
	}
	mac2, err := h.mac2(idCredR, h.peer.Raw, eadRaw)
	if err != nil {
		return nil, err
	}
	if signs {
		if !h.suite.Verify(peerKey, toBeSigned(idCredR, h.th2, h.peer.Raw, eadRaw, mac2), sigOrMAC) {
			return nil, failf("message_2 signature verification failed")
		}
	} else if !macEqual(sigOrMAC, mac2) {
		return nil, failf("message_2 MAC verification failed")
	}
	h.th3 = thNext(h.suite, h.th2, pt, h.peer.Raw)
	return accepted, nil
}
