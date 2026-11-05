package secureenclave

import "fmt"

// The framing of a TPM-wrapped seed, kept free of Windows so it is tested on
// every host. A wrapped seed is one byte saying which hash the RSA-OAEP padding
// used, then the ciphertext, which for the 2048-bit key is exactly 256 bytes.
const (
	tpmWrapSHA256 byte = 1
	tpmWrapSHA1   byte = 2

	tpmWrapKeyBits   = 2048
	tpmWrapCipherLen = tpmWrapKeyBits / 8
)

func packTPMWrap(hash byte, ciphertext []byte) ([]byte, error) {
	if hash != tpmWrapSHA256 && hash != tpmWrapSHA1 {
		return nil, fmt.Errorf("unknown OAEP hash id %d", hash)
	}
	if len(ciphertext) != tpmWrapCipherLen {
		return nil, fmt.Errorf("a %d-bit RSA key produces %d bytes, got %d",
			tpmWrapKeyBits, tpmWrapCipherLen, len(ciphertext))
	}
	return append([]byte{hash}, ciphertext...), nil
}

func unpackTPMWrap(blob []byte) (hash byte, ciphertext []byte, err error) {
	if len(blob) != 1+tpmWrapCipherLen {
		return 0, nil, fmt.Errorf("a TPM-wrapped seed is %d bytes, this is %d", 1+tpmWrapCipherLen, len(blob))
	}
	hash = blob[0]
	if hash != tpmWrapSHA256 && hash != tpmWrapSHA1 {
		return 0, nil, fmt.Errorf("unknown OAEP hash id %d", hash)
	}
	return hash, blob[1:], nil
}
