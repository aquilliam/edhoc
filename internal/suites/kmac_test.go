package suites

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

func TestKMAC256(t *testing.T) {
	f, err := os.Open("testdata/kmac256.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pattern := func(n, start int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(start + 7*i)
		}
		return b
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<16)
	n := 0
	for sc.Scan() {
		var keyLen, dataLen, outLen int
		var want string
		if _, err := fmt.Sscan(sc.Text(), &keyLen, &dataLen, &outLen, &want); err != nil {
			t.Fatal(err)
		}
		got := hex.EncodeToString(kmac256(pattern(keyLen, 1), pattern(dataLen, 2), outLen))
		if got != want {
			t.Errorf("key %d, data %d, output %d: got %s, want %s", keyLen, dataLen, outLen, got, want)
		}
		n++
	}
	if err := sc.Err(); err != nil || n == 0 {
		t.Fatalf("read %d vectors: %v", n, err)
	}
}
