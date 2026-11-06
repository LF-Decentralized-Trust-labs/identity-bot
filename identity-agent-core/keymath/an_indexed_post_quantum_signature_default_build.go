//go:build !kerigo_pqtest

package keymath

import "errors"

// EncodeMLDSA65IndexedSignature is not available in this build: CESR has
// assigned no code for an indexed post-quantum signature, so only a build with
// the kerigo_pqtest tag can write one.
func EncodeMLDSA65IndexedSignature(sig []byte, index, ondex int) (string, error) {
	return "", errors.New("not available in this build")
}

// EncodeMLDSA65CurrentOnlySignature is not available in this build either.
func EncodeMLDSA65CurrentOnlySignature(sig []byte, index int) (string, error) {
	return "", errors.New("not available in this build")
}
