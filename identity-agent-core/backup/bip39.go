package backup

import (
	"crypto/sha512"

	"golang.org/x/crypto/pbkdf2"
)

// bip39PBKDF2 implements BIP39 seed derivation: PBKDF2-HMAC-SHA512, 2048 iterations.
func bip39PBKDF2(mnemonic, passphrase string) ([]byte, error) {
	salt := "mnemonic" + passphrase
	return pbkdf2.Key([]byte(mnemonic), []byte(salt), 2048, 64, sha512.New), nil
}