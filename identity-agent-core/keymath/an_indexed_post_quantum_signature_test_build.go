//go:build kerigo_pqtest

package keymath

import (
	keri "github.com/grapeid/keri-go"
)

// EncodeMLDSA65IndexedSignature writes an ML-DSA-65 signature at the places it
// counts, under keri-go's provisional indexed code. It exists only in a build
// with the kerigo_pqtest tag: CESR has assigned no such code, so a production
// build neither writes nor reads one.
func EncodeMLDSA65IndexedSignature(sig []byte, index, ondex int) (string, error) {
	return keri.EncodeMLDSA65IndexedSignature(sig, keri.SignaturePlace{Index: index, Ondex: ondex})
}

// EncodeMLDSA65CurrentOnlySignature writes an ML-DSA-65 signature that opens no
// prior commitment, as an interaction's is signed, under keri-go's provisional
// current-only code. A test build only, as EncodeMLDSA65IndexedSignature is.
func EncodeMLDSA65CurrentOnlySignature(sig []byte, index int) (string, error) {
	return keri.EncodeMLDSA65IndexedSignature(sig, keri.SignaturePlace{Index: index, CurrentOnly: true})
}
