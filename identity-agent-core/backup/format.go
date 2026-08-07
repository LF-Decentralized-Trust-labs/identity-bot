package backup

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"identity-agent-core/iacrypto"
)

const (
	IABMagic      = "IAB1"
	FormatVersion = 1
)

// Tier identifiers used in manifests and export requests.
const (
	TierCritical  = "tier1"
	TierImportant = "tier2"
	TierFull      = "tier3"
)

// KeySlotType identifies how a BEK wrap slot is unlocked.
type KeySlotType string

const (
	SlotSeedHD     KeySlotType = "seed_hd_v1"
	SlotPassphrase KeySlotType = "passphrase_argon2id_v1"
	SlotGuardianMS KeySlotType = "guardian_multisig_v1"
	// SlotSealedX25519 is unlocked by a private key the agent never had. It is
	// the only slot type that lets a machine write a backup it cannot read.
	SlotSealedX25519 KeySlotType = "sealed_x25519_v1"
)

// SlotPolicy decides whether one way in is enough.
//
// OR means any single slot opens the archive: the phrase, or a passphrase, or
// any one owner's sealed slot. AND means a slot is necessary but not
// sufficient — something one person knows plus something they have.
//
// The distinction is load-bearing rather than decorative. Adding a passphrase
// under OR does not make an archive harder to open; it makes it easier, by
// adding a second independent way in. Only AND makes it harder, and an archive
// that says AND has to mean it.
type SlotPolicy string

const (
	PolicyOR  SlotPolicy = "or"
	PolicyAND SlotPolicy = "and"
)

// Argon2Params pinned in every archive that uses a passphrase slot.
type Argon2Params struct {
	MemoryKiB   uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	SaltLen     uint32 `json:"salt_len"`
}

// SectionMeta describes one logical section inside the encrypted payload.
type SectionMeta struct {
	Name             string `json:"name"`
	DigestBlake3QB64 string `json:"digest_blake3_qb64"`
	SizePlaintext    int    `json:"size_plaintext"`
}

// KeySlot describes one wrapped BEK copy.
type KeySlot struct {
	Type          KeySlotType `json:"type"`
	Policy        SlotPolicy  `json:"policy,omitempty"`
	WrappedBEKB64 string      `json:"wrapped_bek_b64"`
	NonceB64      string      `json:"nonce_b64"`
	Argon2SaltB64 string      `json:"argon2_salt_b64,omitempty"`
	GuardianGroup string      `json:"guardian_group_aid,omitempty"`
	ThresholdM    int         `json:"threshold_m,omitempty"`
	ThresholdN    int         `json:"threshold_n,omitempty"`
	// EphemeralPubB64 is the throwaway public key of a sealed slot. There is
	// deliberately no field naming the recipient: an archive sealed to several
	// owners would otherwise publish who owns the identity to anyone holding a
	// copy of it. Finding the right slot is done by trying them.
	EphemeralPubB64 string `json:"ephemeral_pub_b64,omitempty"`
}

// ExternalDataPointer records lean-residency bulk data (keys/pointers only).
type ExternalDataPointer struct {
	Domain     string `json:"domain"`
	Locator    string `json:"locator"`
	KeyRef     string `json:"key_ref"`
	SizeBytes  int64  `json:"size_bytes,omitempty"`
	ArchivedAt string `json:"archived_at,omitempty"`
}

// Manifest is the cleartext header of every .iab archive.
type Manifest struct {
	FormatVersion        int                   `json:"format_version"`
	CreatedAt            string                `json:"created_at"`
	IdentityAID          string                `json:"identity_aid,omitempty"`
	Tiers                []string              `json:"tiers"`
	SnapshotType         string                `json:"snapshot_type"` // full | delta
	Sections             []SectionMeta         `json:"sections"`
	KeySlots             []KeySlot             `json:"key_slots"`
	SlotPolicy           SlotPolicy            `json:"slot_policy"`
	Argon2Params         *Argon2Params         `json:"argon2_params,omitempty"`
	DeltaStateDigestQB64 string                `json:"delta_state_digest_blake3_qb64,omitempty"`
	ExternalPointers     []ExternalDataPointer `json:"external_pointers,omitempty"`
	PayloadNonceB64      string                `json:"payload_nonce_b64"`

	// AndWrappedBEKB64 and AndNonceB64 are the second layer, present only under
	// AND. There, the slots do not hold the payload key at all — they hold an
	// intermediate secret, and the payload key is wrapped again by that secret
	// combined with the passphrase. Opening a slot therefore gets you halfway
	// and no further, which is what AND has to mean to be worth saying.
	AndWrappedBEKB64 string `json:"and_wrapped_bek_b64,omitempty"`
	AndNonceB64      string `json:"and_nonce_b64,omitempty"`
}

// PayloadBundle is the plaintext structure encrypted under the BEK.
type PayloadBundle struct {
	Sections map[string][]byte `json:"-"`
	Ordered  []PayloadSection  `json:"sections"`
}

type PayloadSection struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
}

// ArchiveFile is the on-disk .iab framing.
// Layout: magic(4) | manifest_len(u32 BE) | manifest JSON | ciphertext
type ArchiveFile struct {
	Manifest   Manifest
	Ciphertext []byte
}

func NewManifest(aid string, tiers []string, snapshotType string) Manifest {
	return Manifest{
		FormatVersion: FormatVersion,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		IdentityAID:   aid,
		Tiers:         tiers,
		SnapshotType:  snapshotType,
		SlotPolicy:    PolicyOR,
	}
}

func DigestSection(data []byte) (string, error) {
	return iacrypto.Blake3QB64(data)
}

func DigestSectionMust(data []byte) string {
	return iacrypto.Blake3QB64Must(data)
}

func (m *Manifest) ValidateSections(bundle *PayloadBundle) error {
	if len(m.Sections) != len(bundle.Ordered) {
		return fmt.Errorf("section count mismatch: manifest %d vs payload %d", len(m.Sections), len(bundle.Ordered))
	}
	for i, sec := range m.Sections {
		if sec.Name != bundle.Ordered[i].Name {
			return fmt.Errorf("section order mismatch at %d: %s vs %s", i, sec.Name, bundle.Ordered[i].Name)
		}
		dig, err := DigestSection(bundle.Ordered[i].Data)
		if err != nil {
			return err
		}
		if dig != sec.DigestBlake3QB64 {
			return fmt.Errorf("digest mismatch for section %s", sec.Name)
		}
	}
	return nil
}

func EncodeArchive(arch *ArchiveFile) ([]byte, error) {
	manifestJSON, err := json.Marshal(arch.Manifest)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if _, err := buf.WriteString(IABMagic); err != nil {
		return nil, err
	}
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(manifestJSON)))
	if _, err := buf.Write(lenBuf); err != nil {
		return nil, err
	}
	if _, err := buf.Write(manifestJSON); err != nil {
		return nil, err
	}
	if _, err := buf.Write(arch.Ciphertext); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func DecodeArchive(data []byte) (*ArchiveFile, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("archive too short")
	}
	if string(data[:4]) != IABMagic {
		return nil, fmt.Errorf("invalid magic: want %s", IABMagic)
	}
	manifestLen := binary.BigEndian.Uint32(data[4:8])
	off := 8
	if int(manifestLen)+off > len(data) {
		return nil, fmt.Errorf("manifest length exceeds file size")
	}
	var manifest Manifest
	if err := json.Unmarshal(data[off:off+int(manifestLen)], &manifest); err != nil {
		return nil, fmt.Errorf("manifest parse: %w", err)
	}
	off += int(manifestLen)
	return &ArchiveFile{
		Manifest:   manifest,
		Ciphertext: data[off:],
	}, nil
}

func SerializePayloadBundle(bundle *PayloadBundle) ([]byte, error) {
	return json.Marshal(bundle.Ordered)
}

func DeserializePayloadBundle(data []byte) (*PayloadBundle, error) {
	var ordered []PayloadSection
	if err := json.Unmarshal(data, &ordered); err != nil {
		return nil, err
	}
	b := &PayloadBundle{Ordered: ordered, Sections: map[string][]byte{}}
	for _, s := range ordered {
		b.Sections[s.Name] = s.Data
	}
	return b, nil
}
