package edhoc

import (
	"context"
	"crypto/ecdh"

	"github.com/aquilliam/edhoc/internal/cbor"
)

// WriteMessage3 returns message_3 (RFC 9528, Section 5.4.2), carrying ead as
// EAD_3. Once it succeeds, Session returns the session.
func (i *Initiator) WriteMessage3(ead ...EAD) ([]byte, error) {
	if i.state != initiatorReadMessage2 {
		return nil, ErrWrongState
	}
	msg, err := i.writeMessage3(ead)
	if err != nil {
		return nil, i.fail(err)
	}
	i.state = initiatorWroteMessage3
	return msg, nil
}

func (i *Initiator) writeMessage3(ead []EAD) ([]byte, error) {
	h := &i.h
	signs := h.cfg.Method.initiatorSigns()
	if signs {
		h.prk4e3m = h.prk3e2m
	} else {
		key, err := h.staticKey()
		if err != nil {
			return nil, err
		}
		gIY, err := key.ECDH(h.peerEph)
		if err != nil {
			return nil, wrapf(err, "computing G_IY")
		}
		if err := h.derivePRK4e3m(gIY); err != nil {
			return nil, err
		}
	}

	cred := &h.cfg.Credential
	eadRaw := appendEAD(nil, ead)
	mac3, err := h.mac3(cred.ID, cred.Raw, eadRaw)
	if err != nil {
		return nil, err
	}
	sigOrMAC := mac3
	if signs {
		sigOrMAC, err = h.suite.Sign(h.signer(), toBeSigned(cred.ID, h.th3, cred.Raw, eadRaw, mac3))
		if err != nil {
			return nil, wrapf(err, "signing message_3")
		}
	}
	// PLAINTEXT_3 = ( ID_CRED_I / bstr / -24..23, Signature_or_MAC_3, ? EAD_3 )
	pt := cred.ID.appendCompact(nil)
	pt = cbor.AppendBytes(pt, sigOrMAC)
	pt = append(pt, eadRaw...)

	ct, err := h.encrypt0(true, h.prk3e2m, labelK3, labelIV3, h.th3, pt)
	if err != nil {
		return nil, err
	}
	h.th4 = thNext(h.suite, h.th3, pt, cred.Raw)
	i.session, err = h.finish(true)
	if err != nil {
		return nil, err
	}
	return cbor.AppendBytes(nil, ct), nil
}

// ReadMessage3 processes message_3 (RFC 9528, Section 5.4.3). It calls
// Config.PeerCredential with ctx to find the Initiator's credential and
// checks the Initiator's proof of possession of the key in it. Once it
// succeeds, Session returns the session. If the Initiator sent an error
// message instead, the error is a *PeerError.
func (r *Responder) ReadMessage3(ctx context.Context, msg []byte) error {
	if r.state != responderWroteMessage2 {
		return ErrWrongState
	}
	if isErrorMessage(msg) {
		return r.fail(parseErrorMessage(msg))
	}
	if err := r.readMessage3(ctx, msg); err != nil {
		return r.fail(err)
	}
	r.state = responderReadMessage3
	return nil
}

func (r *Responder) readMessage3(ctx context.Context, msg []byte) error {
	h := &r.h
	ct, err := readCiphertext(msg, "message_3")
	if err != nil {
		return err
	}
	pt, err := h.encrypt0(false, h.prk3e2m, labelK3, labelIV3, h.th3, ct)
	if err != nil {
		return wrapf(err, "decrypting message_3")
	}

	d := cbor.NewDecoder(pt)
	idCredI, err := readIDCred(d)
	if err != nil {
		return wrapf(err, "malformed PLAINTEXT_3: ID_CRED_I")
	}
	sigOrMAC, err := d.Bytes()
	if err != nil {
		return wrapf(err, "malformed PLAINTEXT_3: Signature_or_MAC_3")
	}
	ead, eadRaw, err := readEAD(d)
	if err != nil {
		return wrapf(err, "malformed PLAINTEXT_3: EAD_3")
	}

	signs := h.cfg.Method.initiatorSigns()
	accepted, err := h.acceptEAD(ead)
	if err != nil {
		return err
	}
	peerKey, err := h.lookupPeer(ctx, idCredI, accepted, h.cR, h.cI, signs)
	if err != nil {
		return err
	}
	if signs {
		h.prk4e3m = h.prk3e2m
	} else {
		gIY, err := h.eph.ECDH(peerKey.(*ecdh.PublicKey))
		if err != nil {
			return wrapf(err, "computing G_IY")
		}
		if err := h.derivePRK4e3m(gIY); err != nil {
			return err
		}
	}
	mac3, err := h.mac3(idCredI, h.peer.Raw, eadRaw)
	if err != nil {
		return err
	}
	if signs {
		if !h.suite.Verify(peerKey, toBeSigned(idCredI, h.th3, h.peer.Raw, eadRaw, mac3), sigOrMAC) {
			return failf("message_3 signature verification failed")
		}
	} else if !macEqual(sigOrMAC, mac3) {
		return failf("message_3 MAC verification failed")
	}
	h.peerEAD = accepted
	h.th4 = thNext(h.suite, h.th3, pt, h.peer.Raw)
	r.session, err = h.finish(false)
	return err
}
