package edhoc_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"log"

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
	if err := responder.ReadMessage1(msg1); err != nil {
		log.Fatal(err)
	}
	msg2, err := responder.WriteMessage2()
	if err != nil {
		log.Fatal(err)
	}
	if err := initiator.ReadMessage2(context.Background(), msg2); err != nil {
		log.Fatal(err)
	}
	msg3, err := initiator.WriteMessage3()
	if err != nil {
		log.Fatal(err)
	}
	if err := responder.ReadMessage3(context.Background(), msg3); err != nil {
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
