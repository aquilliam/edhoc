package edhoc

import (
	"github.com/aquilliam/edhoc/internal/cbor"
	"github.com/aquilliam/edhoc/internal/suites"
)

// th2 computes TH_2 = H(G_Y, H(message_1)) (RFC 9528, Section 5.3.2).
func th2(s *suites.Suite, gY, message1 []byte) []byte {
	in := cbor.AppendBytes(nil, gY)
	in = cbor.AppendBytes(in, s.Sum(message1))
	return s.Sum(in)
}

// thNext computes TH_3 = H(TH_2, PLAINTEXT_2, CRED_R) or
// TH_4 = H(TH_3, PLAINTEXT_3, CRED_I) (RFC 9528, Sections 5.3.2 and 5.4.2).
// cred is the CBOR encoding of the credential, used as it is.
func thNext(s *suites.Suite, th, plaintext, cred []byte) []byte {
	return s.Sum(cbor.AppendBytes(nil, th), plaintext, cred)
}
