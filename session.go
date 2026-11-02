package edhoc

import (
	"bytes"
	"errors"

	"github.com/aquilliam/edhoc/internal/suites"
)

// Exporter labels for OSCORE (RFC 9528, Appendix A.1).
const (
	exporterOSCOREMasterSecret = 0
	exporterOSCOREMasterSalt   = 1
)

const labelKeyUpdate = 11

// A Session is the result of a completed EDHOC handshake. Keys for the
// application are derived from it with Exporter or OSCORE.
//
// The Initiator should not store the session or its keys, or send protected
// application data, until it has received message_4 or a message protected
// with a derived key from the Responder (RFC 9528, Section 5.4.2).
type Session struct {
	suite       *suites.Suite
	initiator   bool
	prkOut      []byte
	prkExporter []byte
	cI, cR      []byte
	peer        Credential
}

func (s *Session) setPRKOut(prkOut []byte) error {
	e, err := kdf(s.suite, prkOut, labelPRKExporter, nil, s.suite.HashLength())
	if err != nil {
		return err
	}
	s.prkOut, s.prkExporter = prkOut, e
	return nil
}

// Exporter derives length bytes of keying material for the application
// (EDHOC_Exporter, RFC 9528, Section 4.2.1). The pair of label and context
// must not be used for two different purposes.
func (s *Session) Exporter(label int, context []byte, length int) ([]byte, error) {
	if label < 0 {
		return nil, errors.New("edhoc: exporter label must not be negative")
	}
	return kdf(s.suite, s.prkExporter, label, context, length)
}

// KeyUpdate replaces PRK_out with one derived from it and context
// (EDHOC_KeyUpdate, RFC 9528, Appendix H). Both sides must use the same
// context. Keys exported before the update stay valid until the application
// deletes them, which it should do as soon as they are no longer needed.
func (s *Session) KeyUpdate(context []byte) error {
	prkOut, err := kdf(s.suite, s.prkOut, labelKeyUpdate, context, s.suite.HashLength())
	if err != nil {
		return err
	}
	old, oldExporter := s.prkOut, s.prkExporter
	if err := s.setPRKOut(prkOut); err != nil {
		return err
	}
	clear(old)
	clear(oldExporter)
	return nil
}

// An OSCOREContext holds the input parameters for an OSCORE security context
// (RFC 8613, Section 3.2) derived from an EDHOC session.
type OSCOREContext struct {
	MasterSecret []byte
	MasterSalt   []byte
	SenderID     []byte
	RecipientID  []byte
	// AEADAlg is the COSE identifier of the AEAD algorithm, such as 10 for
	// AES-CCM-16-64-128.
	AEADAlg int
	// HashAlg is the COSE identifier of the hash used with HKDF, such as -16
	// for SHA-256.
	HashAlg int
}

// OSCORE returns the OSCORE parameters for this session with the default
// lengths from RFC 9528, Appendix A.1: a Master Secret as long as the
// application AEAD key and an 8-byte Master Salt. Use Exporter with labels 0
// and 1 if the application has agreed on other lengths.
func (s *Session) OSCORE() (*OSCOREContext, error) {
	secret, err := s.Exporter(exporterOSCOREMasterSecret, nil, s.suite.AppKeySize)
	if err != nil {
		return nil, err
	}
	salt, err := s.Exporter(exporterOSCOREMasterSalt, nil, 8)
	if err != nil {
		return nil, err
	}
	c := &OSCOREContext{
		MasterSecret: secret,
		MasterSalt:   salt,
		SenderID:     bytes.Clone(s.cR),
		RecipientID:  bytes.Clone(s.cI),
		AEADAlg:      s.suite.AppAEAD,
		HashAlg:      s.suite.AppHash,
	}
	if !s.initiator {
		c.SenderID, c.RecipientID = c.RecipientID, c.SenderID
	}
	return c, nil
}

// Suite returns the selected cipher suite.
func (s *Session) Suite() Suite {
	return Suite(s.suite.ID)
}

// ConnIDs returns the connection identifiers C_I and C_R.
func (s *Session) ConnIDs() (cI, cR []byte) {
	return bytes.Clone(s.cI), bytes.Clone(s.cR)
}

// PeerCredential returns the credential the peer authenticated with.
func (s *Session) PeerCredential() Credential {
	return s.peer
}
