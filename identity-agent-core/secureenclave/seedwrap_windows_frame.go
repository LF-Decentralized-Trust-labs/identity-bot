package secureenclave

import (
	"fmt"
	"os"
	"sync"
)

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

// tpmSeedScheme is the envelope scheme of the TPM wrapper. Declared here, not in
// the Windows file, so the upgrade gate below is tested on every host.
const tpmSeedScheme = "tpm2-rsa2048-oaep"

// TPMWrapExistingSeedEnv is the explicit opt-in to wrapping a seed that is ALREADY
// stored unwrapped under the Windows TPM key, set to "1". Default off.
//
// Why it is off: the TPM wrapper has not been proven on Windows to open a seed
// after a reboot, as another user, or as a service. The wrap-and-open check at
// store time proves only that THIS process can open it. If a later open failed,
// EnsureRootSeed refuses to make a new seed and every key derived from the old
// one is unreadable until restored from backup. Wrapping a NEW seed risks
// nothing that exists; wrapping an existing one does. Turn this on only after a
// Windows test has shown an open after a reboot and as the service user.
const TPMWrapExistingSeedEnv = "IDENTITY_AGENT_TPM_WRAP_EXISTING_SEED"

// mayWrapAnExistingSeed says whether LoadRootSeed may re-wrap a seed that is
// already on disk unwrapped (legacy file or unwrapped envelope) under w. True for
// every wrapper except the TPM one, which needs the opt-in above.
func mayWrapAnExistingSeed(w SeedWrapper) bool {
	if w == nil || w.Scheme() != tpmSeedScheme {
		return true
	}
	return os.Getenv(TPMWrapExistingSeedEnv) == "1"
}

func whyAnExistingSeedIsNotWrapped(w SeedWrapper) string {
	return "wrapping an existing seed under the " + w.Scheme() + " key is off until a test " +
		"proves it opens after a reboot and as the service user; set " + TPMWrapExistingSeedEnv + "=1 to opt in"
}

// provenOnce runs a proof once and remembers its answer; concurrent first callers
// wait for the one run rather than each starting their own.
type provenOnce struct {
	once sync.Once
	ok   bool
}

func (p *provenOnce) do(f func() bool) bool {
	p.once.Do(func() { p.ok = f() })
	return p.ok
}
