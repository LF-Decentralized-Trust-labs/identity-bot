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

// Blake3Digest digests a stream as it is read, so a body need not be held
// whole before its digest is known. Its result is the value Blake3QB64 gives
// for the same bytes.
type Blake3Digest struct{ h *blake3.Hasher }

func NewBlake3Digest() *Blake3Digest { return &Blake3Digest{h: blake3.New()} }

func (d *Blake3Digest) Write(p []byte) (int, error) { return d.h.Write(p) }

// QB64 is the digest of everything written so far, as Blake3QB64 spells it.
func (d *Blake3Digest) QB64() (string, error) {
	var sum [32]byte
	d.h.Sum(sum[:0])
	return MatterFixedQB64("E", sum[:])
}
