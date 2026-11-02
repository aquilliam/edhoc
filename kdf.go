package edhoc

import (
	"crypto/hkdf"

	"github.com/aquilliam/edhoc/internal/cbor"
	"github.com/aquilliam/edhoc/internal/suites"
)

// info_label values for EDHOC_KDF (RFC 9528, Figure 6).
const (
	labelKeystream2  = 0
	labelSalt3e2m    = 1
	labelMAC2        = 2
	labelK3          = 3
	labelIV3         = 4
	labelSalt4e3m    = 5
	labelMAC3        = 6
	labelPRKOut      = 7
	labelK4          = 8
	labelIV4         = 9
	labelPRKExporter = 10
)

// extract is EDHOC_Extract (RFC 9528, Section 4.1.1) for a SHA-2 hash.
func extract(s *suites.Suite, salt, ikm []byte) ([]byte, error) {
	return hkdf.Extract(s.Hash.New, ikm, salt)
}

// kdf is EDHOC_KDF (RFC 9528, Section 4.1.2) for a SHA-2 hash:
// HKDF-Expand(PRK, info, length) with info = (info_label, context, length).
func kdf(s *suites.Suite, prk []byte, label int, context []byte, length int) ([]byte, error) {
	info := cbor.AppendInt(nil, int64(label))
	info = cbor.AppendBytes(info, context)
	info = cbor.AppendUint(info, uint64(length))
	return hkdf.Expand(s.Hash.New, prk, string(info), length)
}
