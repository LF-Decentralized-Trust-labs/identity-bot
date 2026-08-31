package backup

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

// Saying who wrote an archive, so a substituted one can be told from a real one.
//
// Sealing an archive to somebody proves only that it was encrypted TO them. It
// says nothing about who encrypted it — and sealing needs a public key, which
// is public. So anybody at all can write an archive addressed to an owner, and
// that owner opens it successfully, because opening was never a check on
// origin.
//
// What a restore then does with it is the problem: it writes every file the
// archive carries back to its path, and restores contacts, credentials,
// settings and pending requests. A substituted archive is therefore
// attacker-chosen content written into somebody's agent, not merely a failed
// recovery.
//
// The realistic route is a destination rather than somebody being tricked into
// picking a file. Archives are pushed to destinations and fetched back from
// them, so whoever controls one — a rented machine, a cloud account, a holder
// of other people's archives — can swap an archive for another sealed to the
// same owner, and nothing downstream could tell.
//
// TWO KINDS OF WRITER, and they can prove themselves in different ways.
//
// A machine that HAS the recovery words needs no key of its own: the words are
// a secret only the owner has, so a tag keyed from them cannot be produced by
// anybody else. That covers every archive an owner's own agent writes for
// itself.
//
// A machine that does NOT — a paired computer, which holds only the owner's
// public key — cannot use that, and this is where authenticity genuinely needs
// a private key somebody can attribute. It signs with its own, and the owner
// checks that against the key recorded when the machine was paired. Nothing
// has to be co-present: pairing already established which key to expect.

const (
	// WrittenBySeed marks an archive authenticated with a key the recovery
	// words derive.
	WrittenBySeed = "seed"
	// WrittenByMachine marks one signed by the machine that wrote it.
	WrittenByMachine = "machine"
)

// ErrArchiveUnattributed says an archive carries nothing about who wrote it.
//
// Its own error type because it is what every archive written before this
// looks like, and a caller has to be able to tell "made before we recorded
// this" from "the tag is wrong", which is somebody having substituted one.
var ErrArchiveUnattributed = fmt.Errorf("this archive does not say who wrote it")

// SignWithSeed authenticates an archive with a key the recovery words derive.
func SignWithSeed(arch *ArchiveFile, seed []byte) error {
	if len(seed) < 32 {
		return fmt.Errorf("bip39 seed must be at least 32 bytes")
	}
	arch.Manifest.WrittenBy = WrittenBySeed
	arch.Manifest.WriterKeyB64 = ""
	tag, err := archiveTag(arch, authKeyFromSeed(seed))
	if err != nil {
		return err
	}
	arch.Manifest.AuthTagB64 = EncodeB64(tag)
	return nil
}

// SignWithMachineKey authenticates an archive with the writing machine's own
// signing key.
func SignWithMachineKey(arch *ArchiveFile, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("a machine signing key must be %d bytes", ed25519.PrivateKeySize)
	}
	arch.Manifest.WrittenBy = WrittenByMachine
	arch.Manifest.WriterKeyB64 = EncodeB64(priv.Public().(ed25519.PublicKey))
	arch.Manifest.AuthTagB64 = ""
	signed, err := whatIsSigned(arch)
	if err != nil {
		return err
	}
	arch.Manifest.AuthTagB64 = EncodeB64(ed25519.Sign(priv, signed))
	return nil
}

// CheckWhoWroteIt verifies an archive against what the reader expects.
//
// seed authenticates one written from the recovery words. expectedWriterKey is
// the signing key recorded when a machine was paired, and is what makes a
// machine-signed archive mean anything — WITHOUT it, the key in the manifest is
// simply whichever key the writer chose, and an attacker chooses their own. So
// an archive that says a machine wrote it, checked with nothing to check it
// against, is refused rather than passed.
func CheckWhoWroteIt(arch *ArchiveFile, seed []byte, expectedWriterKey []byte) error {
	// The manifest in the file must BE the manifest, not merely decode to it.
	//
	// The mark is computed over the decoded manifest re-marshalled, so a file
	// carrying an unknown field the decoder drops, or a duplicate key whose
	// first copy is a lie, produced different bytes on disk and the same mark.
	// Both verified. A parser that takes the first duplicate then reads
	// something the mark never covered, and any digest or comparison of the
	// file itself is defeated while the check says yes.
	if err := manifestIsCanonical(arch); err != nil {
		return err
	}

	switch arch.Manifest.WrittenBy {
	case "":
		return ErrArchiveUnattributed

	case WrittenBySeed:
		if len(seed) < 32 {
			return fmt.Errorf("this archive was written from the recovery words and none were given")
		}
		claimed, err := DecodeB64(arch.Manifest.AuthTagB64)
		if err != nil {
			return fmt.Errorf("this archive's mark of who wrote it is unreadable")
		}
		want, err := archiveTag(arch, authKeyFromSeed(seed))
		if err != nil {
			return err
		}
		if !hmac.Equal(claimed, want) {
			return fmt.Errorf(
				"this archive was not written by whoever holds these recovery words — " +
					"it may have been replaced with somebody else's")
		}
		return nil

	case WrittenByMachine:
		if len(expectedWriterKey) != ed25519.PublicKeySize {
			// The whole point. A signature checked against the key that came
			// with it proves only that the writer can sign their own work.
			// Says what to do, because this is the ordinary state of a
			// machine that has just been rebuilt rather than a fault.
			//
			// Which machines an identity has is recorded in that identity's
			// OWN backup, so restoring it first is what teaches a fresh
			// machine to check its computer's. That is the order the design
			// already has: the words plus shares bring the identity back, and
			// the recovered identity opens everything else.
			return fmt.Errorf(
				"this archive was written by one of this identity's machines, and this " +
					"agent has no record of which machines those are. Restore this " +
					"identity's own backup first — that is what lists them — or supply " +
					"the machine's signing key")
		}
		if arch.Manifest.WriterKeyB64 != EncodeB64(expectedWriterKey) {
			return fmt.Errorf(
				"this archive was signed by a different machine from the one expected")
		}
		sig, err := DecodeB64(arch.Manifest.AuthTagB64)
		if err != nil {
			return fmt.Errorf("this archive's signature is unreadable")
		}
		signed, err := whatIsSigned(arch)
		if err != nil {
			return err
		}
		if !ed25519.Verify(expectedWriterKey, signed, sig) {
			return fmt.Errorf(
				"this archive's signature does not match its contents — it may have been " +
					"replaced or altered")
		}
		return nil

	default:
		return fmt.Errorf("this archive says it was written in a way this build does not know about")
	}
}

// manifestIsCanonical refuses a file whose manifest bytes are not what
// encoding this manifest produces.
//
// Skipped when there are no raw bytes, which is an archive assembled in memory
// rather than read from a file — there is nothing to disagree with there.
func manifestIsCanonical(arch *ArchiveFile) error {
	if len(arch.RawManifest) == 0 {
		return nil
	}
	canonical, err := json.Marshal(arch.Manifest)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, arch.RawManifest) {
		return fmt.Errorf(
			"this archive's header is not in the form this software writes, so part of it " +
				"is not covered by the mark saying who wrote it")
	}
	return nil
}

// whatIsSigned is the manifest with the mark removed, plus the ciphertext.
//
// The mark cannot cover itself, so it is blanked before the bytes are taken —
// and everything else is covered, INCLUDING the parts of the manifest that are
// cleartext. Signing only the ciphertext would leave the section digests, the
// key slots and the bootstrap envelope free to be edited by anybody.
func whatIsSigned(arch *ArchiveFile) ([]byte, error) {
	bare := arch.Manifest
	bare.AuthTagB64 = ""
	raw, err := json.Marshal(bare)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(raw)+len(arch.Ciphertext))
	out = append(out, raw...)
	return append(out, arch.Ciphertext...), nil
}

func archiveTag(arch *ArchiveFile, key []byte) ([]byte, error) {
	signed, err := whatIsSigned(arch)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(signed)
	return mac.Sum(nil), nil
}

// authKeyFromSeed derives the key that marks an archive as this owner's.
//
// Its own domain, so that a key used to say "I wrote this" is not a key used
// for anything else.
func authKeyFromSeed(seed []byte) []byte {
	r := hkdf.New(sha256.New, seed,
		[]byte("identity-agent-archive-authenticity-salt-v1"),
		[]byte("identity-agent/archive-authenticity/v1"))
	out := make([]byte, 32)
	r.Read(out)
	return out
}
