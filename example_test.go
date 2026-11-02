package edhoc_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/aquilliam/edhoc"
)

// rawPublicKey returns a static DH key and a raw public key credential for
// it, identified by kid.
func rawPublicKey(kid byte) (*ecdh.PrivateKey, edhoc.Credential) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	cred, err := edhoc.NewCCS("", []byte{kid}, key.PublicKey())
	if err != nil {
		log.Fatal(err)
	}
	return key, cred
}

func Example() {
	keyI, credI := rawPublicKey(0x01)
	keyR, credR := rawPublicKey(0x02)

	// Each side knows the other's credential in advance and looks it up by
	// the ID_CRED it is sent.
	known := map[edhoc.IDCred]edhoc.Credential{credI.ID: credI, credR.ID: credR}
	lookUp := func(_ context.Context, p *edhoc.PeerInfo) (edhoc.Credential, error) {
		c, ok := known[p.ID]
		if !ok {
			return edhoc.Credential{}, edhoc.ErrUnknownCredential
		}
		return c, nil
	}

	// A Config can be shared by all sessions on one side. The connection
	// identifier is chosen per session.
	initiator, err := edhoc.NewInitiator(&edhoc.Config{
		Method:         edhoc.MethodStaticStatic,
		Suites:         []edhoc.Suite{edhoc.Suite2},
		Credential:     credI,
		Key:            keyI,
		PeerCredential: lookUp,
	}, []byte{0x37})
	if err != nil {
		log.Fatal(err)
	}
	responder, err := edhoc.NewResponder(&edhoc.Config{
		Method:         edhoc.MethodStaticStatic,
		Suites:         []edhoc.Suite{edhoc.Suite2},
		Credential:     credR,
		Key:            keyR,
		PeerCredential: lookUp,
	}, []byte{0x27})
	if err != nil {
		log.Fatal(err)
	}

	// In a real application each message travels over the network, and a
	// failure on either side is answered with edhoc.ErrorMessage(err).
	msg1, err := initiator.WriteMessage1()
	if err != nil {
		log.Fatal(err)
	}
	if _, err := responder.ReadMessage1(context.Background(), msg1); err != nil {
		log.Fatal(err)
	}
	msg2, err := responder.WriteMessage2()
	if err != nil {
		log.Fatal(err)
	}
	if _, err := initiator.ReadMessage2(context.Background(), msg2); err != nil {
		log.Fatal(err)
	}
	msg3, err := initiator.WriteMessage3()
	if err != nil {
		log.Fatal(err)
	}
	if _, err := responder.ReadMessage3(context.Background(), msg3); err != nil {
		log.Fatal(err)
	}

	si, _ := initiator.Session()
	sr, _ := responder.Session()
	client, _ := si.OSCORE()
	server, _ := sr.OSCORE()
	fmt.Println("same master secret:", bytes.Equal(client.MasterSecret, server.MasterSecret))
	fmt.Printf("client sender ID %x, server sender ID %x\n", client.SenderID, server.SenderID)
	// Output:
	// same master secret: true
	// client sender ID 27, server sender ID 37
}

// A CoAP server for the EDHOC resource (RFC 9528, Appendix A.2) keeps a
// Responder per session between message_1 and message_3 and finds it again by
// the C_R in front of message_3.
func Example_server() {
	keyI, credI := rawPublicKey(0x01)
	keyR, credR := rawPublicKey(0x02)
	cfgR := &edhoc.Config{
		Method:     edhoc.MethodStaticStatic,
		Suites:     []edhoc.Suite{edhoc.Suite2},
		Credential: credR,
		Key:        keyR,
		PeerCredential: func(_ context.Context, p *edhoc.PeerInfo) (edhoc.Credential, error) {
			if p.ID != credI.ID {
				return edhoc.Credential{}, edhoc.ErrUnknownCredential
			}
			return credI, nil
		},
	}

	// A real server guards these with a mutex, limits how many sessions are
	// pending (RFC 9528, Section 9.7) and drops them after a timeout.
	pending := map[string]*edhoc.Responder{}
	nextCR := byte(0)

	// handle serves a POST to /.well-known/edhoc and returns the response
	// payload. When a Read method fails, the payload is the error message,
	// sent with response code 4.00 or 5.00.
	handle := func(ctx context.Context, payload []byte) ([]byte, error) {
		cR, msg, message1, err := edhoc.ParseCoAPRequest(payload)
		if err != nil {
			return nil, err
		}
		if message1 {
			cR := []byte{nextCR}
			nextCR++
			r, err := edhoc.NewResponder(cfgR, cR)
			if err != nil {
				return nil, err
			}
			if _, err := r.ReadMessage1(ctx, msg); err != nil {
				return edhoc.ErrorMessage(err), err
			}
			msg2, err := r.WriteMessage2()
			if err != nil {
				return nil, err
			}
			pending[string(cR)] = r
			return msg2, nil
		}
		r, ok := pending[string(cR)]
		if !ok {
			return nil, errors.New("no session for this C_R")
		}
		delete(pending, string(cR))
		if _, err := r.ReadMessage3(ctx, msg); err != nil {
			return edhoc.ErrorMessage(err), err
		}
		s, _ := r.Session()
		oscore, _ := s.OSCORE()
		fmt.Printf("server: new OSCORE context, sender ID %x, recipient ID %x\n", oscore.SenderID, oscore.RecipientID)
		return r.WriteMessage4()
	}

	// The client.
	ctx := context.Background()
	i, err := edhoc.NewInitiator(&edhoc.Config{
		Method:     edhoc.MethodStaticStatic,
		Suites:     []edhoc.Suite{edhoc.Suite2},
		Credential: credI,
		Key:        keyI,
		PeerCredential: func(_ context.Context, p *edhoc.PeerInfo) (edhoc.Credential, error) {
			if p.ID != credR.ID {
				return edhoc.Credential{}, edhoc.ErrUnknownCredential
			}
			return credR, nil
		},
	}, []byte{0x37})
	if err != nil {
		log.Fatal(err)
	}
	msg1, _ := i.WriteMessage1()
	msg2, err := handle(ctx, edhoc.CoAPMessage1(msg1))
	if err != nil {
		log.Fatal(err)
	}
	if _, err := i.ReadMessage2(ctx, msg2); err != nil {
		log.Fatal(err)
	}
	msg3, _ := i.WriteMessage3()
	s, _ := i.Session()
	_, cR := s.ConnIDs()
	msg4, err := handle(ctx, edhoc.CoAPRequest(cR, msg3))
	if err != nil {
		log.Fatal(err)
	}
	if _, err := i.ReadMessage4(msg4); err != nil {
		log.Fatal(err)
	}
	fmt.Println("client: message_4 received")
	// Output:
	// server: new OSCORE context, sender ID 37, recipient ID 00
	// client: message_4 received
}

// When the Responder rejects the selected cipher suite, the Initiator starts
// a new session with the suites from the error.
func ExampleNewInitiator_retry() {
	ctx := context.Background()
	keyI, credI := rawPublicKey(0x01)
	keyR, credR := rawPublicKey(0x02)
	known := func(c edhoc.Credential) func(context.Context, *edhoc.PeerInfo) (edhoc.Credential, error) {
		return func(context.Context, *edhoc.PeerInfo) (edhoc.Credential, error) { return c, nil }
	}
	cfgI := &edhoc.Config{
		Method:         edhoc.MethodStaticStatic,
		Suites:         []edhoc.Suite{edhoc.Suite3, edhoc.Suite2},
		Credential:     credI,
		Key:            keyI,
		PeerCredential: known(credR),
	}
	cfgR := &edhoc.Config{
		Method:         edhoc.MethodStaticStatic,
		Suites:         []edhoc.Suite{edhoc.Suite2},
		Credential:     credR,
		Key:            keyR,
		PeerCredential: known(credI),
	}

	i, _ := edhoc.NewInitiator(cfgI, []byte{0x37})
	msg1, _ := i.WriteMessage1()
	r, _ := edhoc.NewResponder(cfgR, []byte{0x27})
	_, err := r.ReadMessage1(ctx, msg1)
	reply := edhoc.ErrorMessage(err)

	_, err = i.ReadMessage2(ctx, reply)
	var pe *edhoc.PeerError
	if !errors.As(err, &pe) || pe.Code != edhoc.ErrCodeWrongSelectedSuite {
		log.Fatal(err)
	}
	fmt.Println("Responder supports", pe.Suites)

	i, err = edhoc.NewInitiator(cfgI, []byte{0x37}, pe.Suites...)
	if err != nil {
		log.Fatal(err)
	}
	msg1, _ = i.WriteMessage1()
	r, _ = edhoc.NewResponder(cfgR, []byte{0x27})
	_, err = r.ReadMessage1(ctx, msg1)
	fmt.Println("second message_1 accepted:", err == nil)
	// Output:
	// Responder supports [suite 2 (AES-CCM-16-64-128, SHA-256, 8, P-256, ES256)]
	// second message_1 accepted: true
}

// Both sides send their X.509 certificate by value and check the peer's
// against a shared root in PeerCredential.
func ExampleNewX509() {
	ctx := context.Background()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	// party returns a signing key and a credential with a certificate for it,
	// sent by value.
	party := func(name string, serial int64) (*ecdsa.PrivateKey, edhoc.Credential) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: name},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			log.Fatal(err)
		}
		cred, err := edhoc.NewX509(der)
		if err != nil {
			log.Fatal(err)
		}
		cred.ID = edhoc.X5Chain(der)
		return key, cred
	}

	// verify accepts any certificate issued by the root.
	verify := func(_ context.Context, p *edhoc.PeerInfo) (edhoc.Credential, error) {
		chain, ok := p.ID.X5Chain()
		if !ok {
			return edhoc.Credential{}, edhoc.ErrUnknownCredential
		}
		leaf, err := x509.ParseCertificate(chain[0])
		if err != nil {
			return edhoc.Credential{}, err
		}
		intermediates := x509.NewCertPool()
		for _, der := range chain[1:] {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return edhoc.Credential{}, err
			}
			intermediates.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return edhoc.Credential{}, err
		}
		fmt.Println("verified", leaf.Subject.CommonName)
		return edhoc.NewX509(chain[0])
	}

	keyI, credI := party("phone", 2)
	keyR, credR := party("lock", 3)
	i, err := edhoc.NewInitiator(&edhoc.Config{
		Method:         edhoc.MethodSignSign,
		Suites:         []edhoc.Suite{edhoc.Suite2},
		Credential:     credI,
		Key:            keyI,
		PeerCredential: verify,
	}, []byte{0x37})
	if err != nil {
		log.Fatal(err)
	}
	r, err := edhoc.NewResponder(&edhoc.Config{
		Method:         edhoc.MethodSignSign,
		Suites:         []edhoc.Suite{edhoc.Suite2},
		Credential:     credR,
		Key:            keyR,
		PeerCredential: verify,
	}, []byte{0x27})
	if err != nil {
		log.Fatal(err)
	}

	msg1, _ := i.WriteMessage1()
	if _, err := r.ReadMessage1(ctx, msg1); err != nil {
		log.Fatal(err)
	}
	msg2, _ := r.WriteMessage2()
	if _, err := i.ReadMessage2(ctx, msg2); err != nil {
		log.Fatal(err)
	}
	msg3, _ := i.WriteMessage3()
	if _, err := r.ReadMessage3(ctx, msg3); err != nil {
		log.Fatal(err)
	}
	// Output:
	// verified lock
	// verified phone
}
