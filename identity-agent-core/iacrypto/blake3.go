package iacrypto

import (
	"fmt"

	"github.com/zeebo/blake3"
)

// Blake3QB64 returns a Blake3-256 CESR Diger qb64 (code E, keri 1.1.17 Matter).
func Blake3QB64(data []byte) (string, error) {
	sum := blake3.Sum256(data)
	return MatterFixedQB64("E", sum[:])
}

func Blake3QB64Must(data []byte) string {
	out, err := Blake3QB64(data)
	if err != nil {
		panic(fmt.Sprintf("blake3: %v", err))
	}
	return out
}