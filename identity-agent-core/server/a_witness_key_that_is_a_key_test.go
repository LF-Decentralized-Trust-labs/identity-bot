package server

import (
	"bytes"
	"crypto/ed25519"
)

// aWitnessKey is the public key of a test witness numbered n. The bytes of a
// key are read as a curve point now, so a test cannot stand one up as n
// repeated 32 times; it takes the key of a seed instead.
func aWitnessKey(n byte) []byte {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32)).Public().(ed25519.PublicKey)
}
