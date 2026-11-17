package backup

// The key a utility app's backups are sealed to, and the two things sealed to other keys from it.
//
// A utility app seals its backups to a public key and cannot read them back. The key is one the
// Identity Agent derives, one per utility app and per epoch, from its own root seed; the private
// half is made inside the core when a slot is opened and never handed to an add-on, which is given the
// public key and the result of the opening (see server's BackupSealKeyOf, SealBackupOpenReply and
// ResealBackupSlot). Other implementations check their keys, slots and replies against the committed
// vectors in testdata/seal-app-vectors.json.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// SealAppInfoV1 labels the HKDF of a per-app backup key. It is not SealInfoV1 (a person's key), so the
	// two can never be the same key.
	SealAppInfoV1 = "identity-agent-backup-seal-app-v1"

	// OpenReplyInfoV1 labels the HKDF of the reply that carries a content key to the machine restoring a
	// backup. It is neither slot label, so a reply never opens as a slot.
	OpenReplyInfoV1 = "identity-agent-backup-open-reply-v1"

	// SlotLen is a file-bound slot: ephemeral public key (32), nonce (12), wrapped key and tag (48).
	SlotLen = X25519KeyLen + GCMNonceLen + BEKLen + 16

	// OpenReplyDigestLen is the length of the request digest a reply is bound to.
	OpenReplyDigestLen = 32
)

// DeriveAppSealKeypair derives the X25519 key a utility app's backups are sealed to, from the Identity Agent's root
// seed: HKDF-SHA256, salt SealSaltV1, info = SealAppInfoV1, then the utility app's identifier (its AID in qb64, never
// a display name) preceded by its length in two bytes, then the epoch in four bytes (big endian). The length
// prefix keeps one app's identifier from being read as another's followed by something else.
func DeriveAppSealKeypair(rootSeed []byte, appAID string, epoch uint32) (private, public []byte, err error) {
	if len(rootSeed) < 32 {
		return nil, nil, errors.New("the root seed must be at least 32 bytes")
	}
	if appAID == "" || len(appAID) > 0xffff {
		return nil, nil, errors.New("name the utility app by its identifier")
	}
	if epoch == 0 {
		return nil, nil, errors.New("the epoch starts at 1")
	}
	info := make([]byte, 0, len(SealAppInfoV1)+2+len(appAID)+4)
	info = append(info, SealAppInfoV1...)
	info = binary.BigEndian.AppendUint16(info, uint16(len(appAID)))
	info = append(info, appAID...)
	info = binary.BigEndian.AppendUint32(info, epoch)
	private = make([]byte, X25519KeyLen)
	if _, err := hkdf.New(sha256.New, rootSeed, []byte(SealSaltV1), info).Read(private); err != nil {
		return nil, nil, fmt.Errorf("hkdf backup seal key: %w", err)
	}
	public, err = curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("derive backup seal public key: %w", err)
	}
	return private, public, nil
}

// SealSlotForFile makes a file-bound slot (`sealed_x25519_v2`) for recipientPub: the backup key sealed to it,
// bound to fileID. Layout: ephemeral public key | nonce | wrapped key and tag (SlotLen bytes).
func SealSlotForFile(recipientPub, bek, fileID []byte) ([]byte, error) {
	eph, wrapped, nonce, err := sealBEKForFile(recipientPub, bek, fileID)
	if err != nil {
		return nil, err
	}
	return append(append(append([]byte{}, eph...), nonce...), wrapped...), nil
}

// SealOpenReply seals the content key to the restore key under the reply's own label, with the request digest as
// the authenticated data, so a reply is for one request. Same layout as a slot.
func SealOpenReply(restorePub, bek, digest []byte) ([]byte, error) {
	eph, err := randomBytes(X25519KeyLen)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, GCMNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return sealOpenReplyWith(restorePub, bek, digest, eph, nonce)
}

func sealOpenReplyWith(restorePub, bek, digest, ephPriv, nonce []byte) ([]byte, error) {
	if len(bek) != BEKLen || len(digest) != OpenReplyDigestLen || len(nonce) != GCMNonceLen {
		return nil, errors.New("the content key and the digest are 32 bytes, the nonce 12")
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(ephPriv, restorePub) // refuses a low-order restore key
	if err != nil {
		return nil, fmt.Errorf("seal to the restore key: %w", err)
	}
	kek, err := sharedKEK(shared, ephPub, restorePub, OpenReplyInfoV1)
	if err != nil {
		return nil, err
	}
	gcm, err := gcmFor(kek)
	if err != nil {
		return nil, err
	}
	return append(append(append([]byte{}, ephPub...), nonce...), gcm.Seal(nil, nonce, bek, digest)...), nil
}
