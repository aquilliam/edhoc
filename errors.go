package edhoc

import (
	"errors"
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/aquilliam/edhoc/internal/cbor"
)

// An ErrCode is an ERR_CODE value of an EDHOC error message (RFC 9528,
// Section 6).
type ErrCode int

// The ERR_CODE values defined in RFC 9528, Section 6.
const (
	ErrCodeUnspecified        ErrCode = 1
	ErrCodeWrongSelectedSuite ErrCode = 2
	ErrCodeUnknownCredential  ErrCode = 3
)

func (c ErrCode) String() string {
	switch c {
	case ErrCodeUnspecified:
		return "unspecified error"
	case ErrCodeWrongSelectedSuite:
		return "wrong selected cipher suite"
	case ErrCodeUnknownCredential:
		return "unknown credential referenced"
	}
	return fmt.Sprintf("error code %d", int(c))
}

// ErrWrongState is returned when a method of an Initiator or Responder is
// called out of order or after the session has failed, and when a Session is
// used after Close.
var ErrWrongState = errors.New("edhoc: method called in the wrong state")

// ErrUnknownCredential is returned by a Config.PeerCredential function when
// the peer refers to a credential this side does not have.
var ErrUnknownCredential = errors.New("edhoc: unknown credential")

// An Error is a failure found while processing an EDHOC message. The session
// is over; pass the error to ErrorMessage to get the error message to send to
// the peer.
//
// An application that rejects a message for a reason of its own, such as an
// EAD item it cannot process (RFC 9528, Section 3.8), can send
// ErrorMessage(&Error{Code: ErrCodeUnspecified, Info: "..."}) and drop the
// session.
type Error struct {
	// Code is the ERR_CODE to send.
	Code ErrCode
	// Info is the diagnostic text sent with ErrCodeUnspecified.
	Info string
	// Suites is SUITES_R, sent with ErrCodeWrongSelectedSuite.
	Suites []Suite

	err error
}

func (e *Error) Error() string {
	if e.err != nil {
		return "edhoc: " + e.Info + ": " + e.err.Error()
	}
	return "edhoc: " + e.Info
}

func (e *Error) Unwrap() error { return e.err }

func failf(format string, args ...any) *Error {
	return &Error{Code: ErrCodeUnspecified, Info: fmt.Sprintf(format, args...)}
}

func wrapf(err error, format string, args ...any) *Error {
	return &Error{Code: ErrCodeUnspecified, Info: fmt.Sprintf(format, args...), err: err}
}

// A PeerError is an EDHOC error message received from the peer.
type PeerError struct {
	Code ErrCode
	// Info is the diagnostic text sent with ErrCodeUnspecified.
	Info string
	// Suites is SUITES_R, sent with ErrCodeWrongSelectedSuite. Use it as
	// the peerSuites argument of NewInitiator when starting the next session.
	Suites []Suite
}

func (e *PeerError) Error() string {
	switch e.Code {
	case ErrCodeUnspecified:
		return fmt.Sprintf("edhoc: peer sent error: %q", e.Info)
	case ErrCodeWrongSelectedSuite:
		return fmt.Sprintf("edhoc: peer does not accept the selected cipher suite; it supports %v", e.Suites)
	case ErrCodeUnknownCredential:
		return "edhoc: peer does not know the credential we referred to"
	}
	return fmt.Sprintf("edhoc: peer sent error code %d", int(e.Code))
}

// ErrorMessage returns the EDHOC error message to send to the peer after err,
// or nil if no error message should be sent. Only errors of type *Error get a
// reply; misuse of the API and errors received from the peer do not.
func ErrorMessage(err error) []byte {
	var e *Error
	if !errors.As(err, &e) {
		return nil
	}
	b := cbor.AppendInt(nil, int64(e.Code))
	switch e.Code {
	case ErrCodeWrongSelectedSuite:
		b = appendSuites(b, e.Suites)
	case ErrCodeUnknownCredential:
		b = append(b, 0xf5)
	default:
		info := e.Info
		if !utf8.ValidString(info) {
			info = ""
		}
		b = cbor.AppendText(b, info)
	}
	return b
}

// isErrorMessage reports whether msg, received where a message_2, message_3
// or message_4 was expected, is an error message. Those messages start with a
// byte string, and an error message starts with an integer.
func isErrorMessage(msg []byte) bool {
	d := cbor.NewDecoder(msg)
	m, ok := d.Major()
	return ok && (m == 0 || m == 1)
}

// parseErrorMessage decodes an error message.
func parseErrorMessage(msg []byte) error {
	d := cbor.NewDecoder(msg)
	code, err := d.Int()
	if err != nil {
		return errors.New("edhoc: malformed error message")
	}
	if code < math.MinInt || code > math.MaxInt {
		return errors.New("edhoc: malformed error message")
	}
	pe := &PeerError{Code: ErrCode(code)}
	switch pe.Code {
	case ErrCodeUnspecified:
		pe.Info, err = d.Text()
	case ErrCodeWrongSelectedSuite:
		pe.Suites, err = readSuites(d)
	default:
		_, err = d.Raw()
	}
	if err != nil || !d.Done() {
		return errors.New("edhoc: malformed error message")
	}
	return pe
}

// appendSuites appends SUITES_I or SUITES_R: an int for a single suite,
// otherwise an array.
func appendSuites(b []byte, s []Suite) []byte {
	if len(s) == 1 {
		return cbor.AppendInt(b, int64(s[0]))
	}
	b = cbor.AppendArray(b, len(s))
	for _, v := range s {
		b = cbor.AppendInt(b, int64(v))
	}
	return b
}

// readSuites reads SUITES_I or SUITES_R. An array must have at least two
// elements (RFC 9528, Section 5.2.1).
func readSuites(d *cbor.Decoder) ([]Suite, error) {
	if m, _ := d.Major(); m != 4 {
		v, err := readSuite(d)
		if err != nil {
			return nil, err
		}
		return []Suite{v}, nil
	}
	n, err := d.Array()
	if err != nil {
		return nil, err
	}
	if n < 2 {
		return nil, cbor.ErrNotDeterministic
	}
	s := make([]Suite, 0, n)
	for range n {
		v, err := readSuite(d)
		if err != nil {
			return nil, err
		}
		s = append(s, v)
	}
	return s, nil
}

func readSuite(d *cbor.Decoder) (Suite, error) {
	v, err := d.Int()
	if err != nil {
		return 0, err
	}
	if v < -65536 || v > 65535 {
		return 0, cbor.ErrUnsupported
	}
	return Suite(v), nil
}
