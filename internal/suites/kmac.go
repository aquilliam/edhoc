package suites

import "crypto/sha3"

// kmac256 returns KMAC256(key, x, 8*length, "") (NIST SP 800-185, Section
// 4.3).
func kmac256(key, x []byte, length int) []byte {
	const rate = 136
	h := sha3.NewCSHAKE256([]byte("KMAC"), nil)
	pad := leftEncode(nil, rate)
	pad = leftEncode(pad, uint64(8*len(key)))
	pad = append(pad, key...)
	pad = append(pad, make([]byte, (rate-len(pad)%rate)%rate)...)
	h.Write(pad)
	h.Write(x)
	h.Write(rightEncode(uint64(8 * length)))
	out := make([]byte, length)
	h.Read(out)
	return out
}

// leftEncode appends left_encode(x) (NIST SP 800-185, Section 2.3.1).
func leftEncode(b []byte, x uint64) []byte {
	n := encodedLen(x)
	b = append(b, byte(n))
	for i := n - 1; i >= 0; i-- {
		b = append(b, byte(x>>(8*i)))
	}
	return b
}

// rightEncode returns right_encode(x) (NIST SP 800-185, Section 2.3.1).
func rightEncode(x uint64) []byte {
	n := encodedLen(x)
	b := make([]byte, 0, n+1)
	for i := n - 1; i >= 0; i-- {
		b = append(b, byte(x>>(8*i)))
	}
	return append(b, byte(n))
}

func encodedLen(x uint64) int {
	n := 1
	for x >= 1<<(8*n) && n < 8 {
		n++
	}
	return n
}
