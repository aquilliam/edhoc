package edhoc

import (
	"errors"

	"github.com/aquilliam/edhoc/internal/cbor"
)

// cborTrue is the CBOR simple value true.
const cborTrue = 0xf5

// CoAPMessage1 returns the payload of the CoAP request that carries message_1
// to the EDHOC resource: msg prefixed with the CBOR value true (RFC 9528,
// Appendix A.2).
func CoAPMessage1(msg []byte) []byte {
	return append([]byte{cborTrue}, msg...)
}

// CoAPRequest returns the payload of a CoAP request that carries message_3 or
// an error message to the EDHOC resource: msg prefixed with C_R, the
// Responder's connection identifier (RFC 9528, Appendix A.2).
func CoAPRequest(cR, msg []byte) []byte {
	return append(cbor.AppendID(nil, cR), msg...)
}

// ParseCoAPRequest splits the payload of a CoAP request to the EDHOC
// resource. For message_1, message1 is true and cR is nil. Otherwise cR is the
// connection identifier that selects the Responder msg is for. cR and msg
// share memory with payload.
func ParseCoAPRequest(payload []byte) (cR, msg []byte, message1 bool, err error) {
	if len(payload) > 0 && payload[0] == cborTrue {
		return nil, payload[1:], true, nil
	}
	d := cbor.NewDecoder(payload)
	cR, err = d.ID()
	if err != nil {
		return nil, nil, false, errors.New("edhoc: malformed connection identifier in CoAP payload")
	}
	return cR, d.Rest(), false, nil
}
