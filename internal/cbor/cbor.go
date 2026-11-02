// Package cbor encodes and decodes the subset of CBOR (RFC 8949) used by
// EDHOC.
//
// EDHOC messages are deterministically encoded (RFC 9528, Section 3.1), so the
// decoder rejects anything that is not: arguments that are longer than
// necessary, indefinite lengths, and map keys that are out of order or
// repeated. Floating-point values and simple values other than false, true,
// null and undefined are not supported.
package cbor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"unicode/utf8"
)

const (
	majorUint   = 0
	majorNeg    = 1
	majorBytes  = 2
	majorText   = 3
	majorArray  = 4
	majorMap    = 5
	majorTag    = 6
	majorSimple = 7
)

// maxDepth limits how deeply arrays, maps and tags may nest in Decoder.Raw.
const maxDepth = 16

var (
	// ErrMalformed means the data is not well-formed CBOR.
	ErrMalformed = errors.New("cbor: malformed data")
	// ErrNotDeterministic means the data is well-formed but not
	// deterministically encoded.
	ErrNotDeterministic = errors.New("cbor: not deterministically encoded")
	// ErrUnsupported means the data uses a feature this package does not
	// handle, such as a floating-point value.
	ErrUnsupported = errors.New("cbor: unsupported data item")
	// ErrType means the next data item is not of the requested type.
	ErrType = errors.New("cbor: unexpected type")
)

func appendHead(b []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(b, m|byte(n))
	case n <= math.MaxUint8:
		return append(b, m|24, byte(n))
	case n <= math.MaxUint16:
		return binary.BigEndian.AppendUint16(append(b, m|25), uint16(n))
	case n <= math.MaxUint32:
		return binary.BigEndian.AppendUint32(append(b, m|26), uint32(n))
	}
	return binary.BigEndian.AppendUint64(append(b, m|27), n)
}

// AppendUint appends the encoding of an unsigned integer.
func AppendUint(b []byte, v uint64) []byte {
	return appendHead(b, majorUint, v)
}

// AppendInt appends the encoding of a signed integer.
func AppendInt(b []byte, v int64) []byte {
	if v < 0 {
		return appendHead(b, majorNeg, uint64(-1-v))
	}
	return appendHead(b, majorUint, uint64(v))
}

// AppendBytes appends the encoding of a byte string.
func AppendBytes(b, v []byte) []byte {
	return append(appendHead(b, majorBytes, uint64(len(v))), v...)
}

// AppendText appends the encoding of a text string. The caller must make sure
// s is valid UTF-8.
func AppendText(b []byte, s string) []byte {
	return append(appendHead(b, majorText, uint64(len(s))), s...)
}

// AppendArray appends the header of an array with n elements.
func AppendArray(b []byte, n int) []byte {
	return appendHead(b, majorArray, uint64(n))
}

// AppendMap appends the header of a map with n key/value pairs.
func AppendMap(b []byte, n int) []byte {
	return appendHead(b, majorMap, uint64(n))
}

// isOneByteInt reports whether c is the complete encoding of an integer in
// the range -24..23.
func isOneByteInt(c byte) bool {
	return c <= 0x17 || (c >= 0x20 && c <= 0x37)
}

// AppendID appends a byte string identifier as described in RFC 9528,
// Section 3.3.2. A one-byte identifier that is also the encoding of an
// integer in -24..23 is written as that byte; anything else is written as a
// byte string.
func AppendID(b, id []byte) []byte {
	if len(id) == 1 && isOneByteInt(id[0]) {
		return append(b, id[0])
	}
	return AppendBytes(b, id)
}

// A Decoder reads a sequence of CBOR data items from a byte slice. Byte
// strings it returns share memory with the input.
//
// When a method returns an error, the Decoder has not moved past the item it
// was trying to read.
type Decoder struct {
	data []byte
	off  int
}

// NewDecoder returns a Decoder that reads from data.
func NewDecoder(data []byte) *Decoder {
	return &Decoder{data: data}
}

// Done reports whether every byte of the input has been read.
func (d *Decoder) Done() bool {
	return d.off == len(d.data)
}

// Rest returns the input that has not been read yet.
func (d *Decoder) Rest() []byte {
	return d.data[d.off:]
}

// head reads the initial byte and argument of the next data item. For major
// type 7 it returns the additional information in arg and reads nothing more.
func (d *Decoder) head() (major byte, arg uint64, err error) {
	if d.off >= len(d.data) {
		return 0, 0, ErrMalformed
	}
	c := d.data[d.off]
	major, ai := c>>5, c&0x1f
	if major == majorSimple {
		if ai == 31 {
			return 0, 0, ErrMalformed
		}
		d.off++
		return major, uint64(ai), nil
	}
	var n int
	switch {
	case ai < 24:
		d.off++
		return major, uint64(ai), nil
	case ai == 24:
		n = 1
	case ai == 25:
		n = 2
	case ai == 26:
		n = 4
	case ai == 27:
		n = 8
	case ai == 31 && major >= majorBytes && major <= majorMap:
		return 0, 0, ErrNotDeterministic
	default:
		return 0, 0, ErrMalformed
	}
	if len(d.data)-d.off-1 < n {
		return 0, 0, ErrMalformed
	}
	p := d.data[d.off+1 : d.off+1+n]
	var min uint64
	switch n {
	case 1:
		arg, min = uint64(p[0]), 24
	case 2:
		arg, min = uint64(binary.BigEndian.Uint16(p)), math.MaxUint8+1
	case 4:
		arg, min = uint64(binary.BigEndian.Uint32(p)), math.MaxUint16+1
	case 8:
		arg, min = binary.BigEndian.Uint64(p), math.MaxUint32+1
	}
	if arg < min {
		return 0, 0, ErrNotDeterministic
	}
	d.off += 1 + n
	return major, arg, nil
}

// Major returns the major type of the next data item without reading it.
func (d *Decoder) Major() (byte, bool) {
	if d.off >= len(d.data) {
		return 0, false
	}
	return d.data[d.off] >> 5, true
}

// expect reads the head of the next data item and checks its major type.
func (d *Decoder) expect(major byte) (uint64, error) {
	start := d.off
	m, arg, err := d.head()
	if err != nil {
		return 0, err
	}
	if m != major {
		d.off = start
		return 0, ErrType
	}
	return arg, nil
}

// Uint reads an unsigned integer.
func (d *Decoder) Uint() (uint64, error) {
	return d.expect(majorUint)
}

// Int reads an integer that fits in an int64.
func (d *Decoder) Int() (int64, error) {
	start := d.off
	m, arg, err := d.head()
	if err != nil {
		return 0, err
	}
	if m != majorUint && m != majorNeg {
		d.off = start
		return 0, ErrType
	}
	if arg > math.MaxInt64 {
		d.off = start
		return 0, ErrUnsupported
	}
	if m == majorNeg {
		return -1 - int64(arg), nil
	}
	return int64(arg), nil
}

// str reads the contents of a byte or text string.
func (d *Decoder) str(major byte) ([]byte, error) {
	start := d.off
	n, err := d.expect(major)
	if err != nil {
		return nil, err
	}
	if n > uint64(len(d.data)-d.off) {
		d.off = start
		return nil, ErrMalformed
	}
	v := d.data[d.off : d.off+int(n)]
	if major == majorText && !utf8.Valid(v) {
		d.off = start
		return nil, ErrMalformed
	}
	d.off += int(n)
	return v, nil
}

// Bytes reads a byte string.
func (d *Decoder) Bytes() ([]byte, error) {
	return d.str(majorBytes)
}

// Text reads a text string.
func (d *Decoder) Text() (string, error) {
	v, err := d.str(majorText)
	return string(v), err
}

// count reads an array or map header.
func (d *Decoder) count(major byte) (int, error) {
	start := d.off
	n, err := d.expect(major)
	if err != nil {
		return 0, err
	}
	// Every element takes at least one byte.
	if n > uint64(len(d.data)-d.off) {
		d.off = start
		return 0, ErrMalformed
	}
	return int(n), nil
}

// Array reads an array header and returns the number of elements.
func (d *Decoder) Array() (int, error) {
	return d.count(majorArray)
}

// Map reads a map header and returns the number of key/value pairs. The
// caller reads the pairs and is responsible for checking key order; Raw does
// this for a whole map.
func (d *Decoder) Map() (int, error) {
	return d.count(majorMap)
}

// ID reads a byte string identifier as described in RFC 9528, Section 3.3.2.
// It rejects a one-byte byte string that should have been sent as an integer.
func (d *Decoder) ID() ([]byte, error) {
	if d.off >= len(d.data) {
		return nil, ErrMalformed
	}
	if c := d.data[d.off]; isOneByteInt(c) {
		d.off++
		return d.data[d.off-1 : d.off], nil
	}
	start := d.off
	v, err := d.Bytes()
	if err != nil {
		return nil, err
	}
	if len(v) == 1 && isOneByteInt(v[0]) {
		d.off = start
		return nil, ErrNotDeterministic
	}
	return v, nil
}

// Raw reads one complete data item, checks that it is deterministically
// encoded, and returns its encoding.
func (d *Decoder) Raw() ([]byte, error) {
	start := d.off
	if err := d.skip(0); err != nil {
		d.off = start
		return nil, err
	}
	return d.data[start:d.off], nil
}

func (d *Decoder) skip(depth int) error {
	if depth > maxDepth {
		return ErrUnsupported
	}
	m, arg, err := d.head()
	if err != nil {
		return err
	}
	switch m {
	case majorUint, majorNeg:
		return nil
	case majorBytes, majorText:
		if arg > uint64(len(d.data)-d.off) {
			return ErrMalformed
		}
		v := d.data[d.off : d.off+int(arg)]
		if m == majorText && !utf8.Valid(v) {
			return ErrMalformed
		}
		d.off += int(arg)
		return nil
	case majorArray:
		if arg > uint64(len(d.data)-d.off) {
			return ErrMalformed
		}
		for range arg {
			if err := d.skip(depth + 1); err != nil {
				return err
			}
		}
		return nil
	case majorMap:
		if arg > uint64(len(d.data)-d.off) {
			return ErrMalformed
		}
		var prev []byte
		for i := range arg {
			k := d.off
			if err := d.skip(depth + 1); err != nil {
				return err
			}
			key := d.data[k:d.off]
			if i > 0 {
				switch bytes.Compare(prev, key) {
				case 0:
					return ErrMalformed
				case 1:
					return ErrNotDeterministic
				}
			}
			prev = key
			if err := d.skip(depth + 1); err != nil {
				return err
			}
		}
		return nil
	case majorTag:
		return d.skip(depth + 1)
	}
	// Major type 7: false, true, null and undefined only.
	if arg >= 20 && arg <= 23 {
		return nil
	}
	if arg >= 28 {
		return ErrMalformed
	}
	return ErrUnsupported
}
