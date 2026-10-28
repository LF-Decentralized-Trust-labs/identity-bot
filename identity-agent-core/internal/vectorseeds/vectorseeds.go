// Package vectorseeds is the shape in which a vector file publishes the seeds
// of a keyset. It holds the type only: the vector packages embed it in what
// they publish, and only their tests import internal/fixedkeys, which turns
// the seeds into keys.
package vectorseeds

// Seeds are a keyset's seeds, hex: 32 bytes each for ed25519, mldsa65 and
// x25519, 64 for mlkem768.
type Seeds struct {
	Ed25519  string `json:"ed25519"`
	MLDSA65  string `json:"mldsa65"`
	X25519   string `json:"x25519"`
	MLKEM768 string `json:"mlkem768"`
}
