package edhoc

import (
	"bytes"
	"math"
	"slices"

	"github.com/aquilliam/edhoc/internal/cbor"
)

// appendEAD appends an EAD field: a sequence of ead_label and optional
// ead_value pairs (RFC 9528, Section 3.8).
func appendEAD(b []byte, items []EAD) []byte {
	for _, e := range items {
		b = cbor.AppendInt(b, int64(e.Label))
		if e.Value != nil {
			b = cbor.AppendBytes(b, e.Value)
		}
	}
	return b
}

// readEAD reads an EAD field that runs to the end of d. It returns the items
// and their encoding, which is what goes into context_2 and context_3.
func readEAD(d *cbor.Decoder) ([]EAD, []byte, error) {
	raw := d.Rest()
	var items []EAD
	for !d.Done() {
		label, err := d.Int()
		if err != nil {
			return nil, nil, err
		}
		if label < math.MinInt || label > math.MaxInt {
			return nil, nil, cbor.ErrUnsupported
		}
		e := EAD{Label: int(label)}
		if m, _ := d.Major(); m == 2 {
			v, err := d.Bytes()
			if err != nil {
				return nil, nil, err
			}
			e.Value = append([]byte{}, v...)
		}
		items = append(items, e)
	}
	return items, bytes.Clone(raw), nil
}

// acceptEAD drops padding and fails if a critical item has a label the
// application did not list in Config.EADLabels.
func (h *handshake) acceptEAD(items []EAD) ([]EAD, error) {
	var out []EAD
	for _, e := range items {
		if e.Label == 0 {
			continue
		}
		if e.Label < 0 && !slices.Contains(h.cfg.EADLabels, -e.Label) {
			return nil, failf("unsupported critical EAD item %d", e.Label)
		}
		out = append(out, e)
	}
	return out, nil
}
