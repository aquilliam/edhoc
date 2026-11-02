package suites

import (
	"crypto/ecdh"
	"errors"
	"math/big"
)

var errInvalidPoint = errors.New("suites: invalid public key")

// curve holds what is needed to recover a point on a short Weierstrass curve
// y² = x³ - 3x + b from its x-coordinate.
type curve struct {
	size int
	p, b *big.Int
	// sqrtExp is (p+1)/4. Both NIST curves used by EDHOC have p ≡ 3 mod 4, so
	// a square root of v is v^((p+1)/4).
	sqrtExp *big.Int
}

func newCurve(size int, p, b string) *curve {
	c := &curve{size: size, p: mustHex(p), b: mustHex(b)}
	c.sqrtExp = new(big.Int).Rsh(new(big.Int).Add(c.p, big.NewInt(1)), 2)
	return c
}

func mustHex(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("suites: bad curve constant")
	}
	return v
}

// P-256 parameters from SEC 2, Section 2.4.2.
var p256 = newCurve(32,
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")

// P-384 parameters from SEC 2, Section 2.5.1.
var p384 = newCurve(48,
	"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
	"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef")

// decompress recovers a point from its x-coordinate, following RFC 9528,
// Appendix B. Either square root gives the same ECDH result, so the sign of y
// is not needed. The x-coordinate is public, so variable-time arithmetic is
// fine here.
func (c *curve) decompress(ec ecdh.Curve, xb []byte) (*ecdh.PublicKey, error) {
	if len(xb) != c.size {
		return nil, errInvalidPoint
	}
	x := new(big.Int).SetBytes(xb)
	if x.Cmp(c.p) >= 0 {
		return nil, errInvalidPoint
	}
	// v = x³ - 3x + b
	v := new(big.Int).Mul(x, x)
	v.Mul(v, x)
	t := new(big.Int).Lsh(x, 1)
	t.Add(t, x)
	v.Sub(v, t)
	v.Add(v, c.b)
	v.Mod(v, c.p)

	y := new(big.Int).Exp(v, c.sqrtExp, c.p)
	if new(big.Int).Exp(y, big.NewInt(2), c.p).Cmp(v) != 0 {
		return nil, errInvalidPoint
	}
	point := make([]byte, 1+2*c.size)
	point[0] = 4
	x.FillBytes(point[1 : 1+c.size])
	y.FillBytes(point[1+c.size:])
	return ec.NewPublicKey(point)
}
