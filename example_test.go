package edhoc_test

import (
	"bytes"
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
	// the kid it is sent.
	knows := func(c edhoc.Credential) func(edhoc.IDCred) (edhoc.Credential, error) {
		return func(id edhoc.IDCred) (edhoc.Credential, error) {
			if !id.Equal(c.ID) {
				return edhoc.Credential{}, edhoc.ErrUnknownCredential
			}
			return c, nil
		}
	}

	initiator, err := edhoc.NewInitiator(&edhoc.Config{
		Method:         edhoc.MethodStaticStatic,
		Suites:         []edhoc.Suite{edhoc.Suite2},
		ConnID:         []byte{0x37},
		Credential:     credI,
		Key:            keyI,
		PeerCredential: knows(credR),
	})
	if err != nil {
		log.Fatal(err)
	}
	responder, err := edhoc.NewResponder(&edhoc.Config{
		Method:         edhoc.MethodStaticStatic,
		Suites:         []edhoc.Suite{edhoc.Suite2},
		ConnID:         []byte{0x27},
		Credential:     credR,
		Key:            keyR,
		PeerCredential: knows(credI),
	})
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
	if err := initiator.ReadMessage2(msg2); err != nil {
		log.Fatal(err)
	}
	msg3, err := initiator.WriteMessage3()
	if err != nil {
		log.Fatal(err)
	}
	if err := responder.ReadMessage3(msg3); err != nil {
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
