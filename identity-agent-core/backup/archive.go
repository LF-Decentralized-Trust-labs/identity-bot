package backup

import (
	"crypto/rand"
	"fmt"
)

// ExportRequest parameters for creating an archive.
type ExportRequest struct {
	Mnemonic             string
	Passphrase           string // optional — adds passphrase slot
	Tiers                []string
	SnapshotType         string // full | delta
	BIP39Seed            []byte // alternative to Mnemonic (API may pass derived seed)
	GuardianSlots        []KeySlot
	SlotPolicy           SlotPolicy
	Bundle               *PayloadBundle
	ExternalPointers     []ExternalDataPointer
	DeltaStateDigestQB64 string
	// SealToPublicKeys adds one sealed slot per recipient, letting an agent
	// export without ever being told the seed phrase. Any one of them opens
	// the archive.
	SealToPublicKeys [][]byte
}

// ExportResult describes a completed export.
type ExportResult struct {
	Bytes        []byte
	Manifest     Manifest
	Size         int
	Tiers        []string
	SnapshotType string
}

// CreateArchive builds an encrypted .iab from collected data.
func (c *Collector) CreateArchive(opts CollectOptions, req ExportRequest) (*ExportResult, error) {
	// An archive nobody can open is worse than no archive, so there must be at
	// least one way in. Sealing counts: it needs no secret here, which is the
	// whole point of it.
	if req.Mnemonic == "" && len(req.BIP39Seed) == 0 && len(req.SealToPublicKeys) == 0 {
		return nil, fmt.Errorf("no way to unlock this archive: provide a mnemonic, a bip39 seed, or at least one public key to seal to")
	}

	var bundle *PayloadBundle
	var pointers []ExternalDataPointer
	var err error
	if req.Bundle != nil {
		bundle = req.Bundle
		pointers = req.ExternalPointers
	} else {
		bundle, pointers, err = c.Collect(opts)
		if err != nil {
			return nil, err
		}
	}

	// The AID is a label on the manifest, not something the archive depends on,
	// so its absence must not stop a backup. Reaching through a nil store to
	// find that out would panic mid-export and lose the run.
	aid := ""
	if c.Store != nil {
		if identity, _ := c.Store.GetIdentity(); identity != nil {
			aid = identity.AID
		}
	}

	snapshotType := req.SnapshotType
	if snapshotType == "" {
		snapshotType = "full"
	}

	tiers := opts.Tiers
	if len(tiers) == 0 {
		tiers = []string{TierCritical}
	}

	manifest := NewManifest(aid, tiers, snapshotType)
	manifest.ExternalPointers = pointers
	manifest.DeltaStateDigestQB64 = req.DeltaStateDigestQB64
	if req.SlotPolicy != "" {
		manifest.SlotPolicy = req.SlotPolicy
	}

	for _, sec := range bundle.Ordered {
		dig := DigestSectionMust(sec.Data)
		manifest.Sections = append(manifest.Sections, SectionMeta{
			Name:             sec.Name,
			DigestBlake3QB64: dig,
			SizePlaintext:    len(sec.Data),
		})
	}

	plainPayload, err := SerializePayloadBundle(bundle)
	if err != nil {
		return nil, err
	}

	bek, err := NewBEK()
	if err != nil {
		return nil, err
	}

	ciphertext, payloadNonce, err := EncryptPayload(bek, plainPayload)
	if err != nil {
		return nil, err
	}
	manifest.PayloadNonceB64 = EncodeB64(payloadNonce)

	// Under AND, the slots stop holding the payload key and hold this instead.
	// Opening a slot then yields a secret that is useless on its own, and the
	// payload key is reached only by combining it with the passphrase.
	//
	// Everything below writes `slotSecret` into slots without knowing which
	// mode it is in, so there is exactly one place where OR and AND differ —
	// here — rather than a branch in every slot type.
	requireAll := manifest.SlotPolicy == PolicyAND
	slotSecret := bek
	if requireAll {
		if req.Passphrase == "" {
			return nil, fmt.Errorf("an AND archive needs a passphrase as its second factor, and none was given")
		}
		if slotSecret, err = NewBEK(); err != nil {
			return nil, err
		}
	}

	// Seed slot — only when the caller actually holds the seed. An agent
	// exporting on a machine it does not own has no seed to offer, and asking
	// it for one is the thing sealing exists to avoid.
	var bip39Seed []byte
	if len(req.BIP39Seed) > 0 {
		bip39Seed = req.BIP39Seed
	} else if req.Mnemonic != "" {
		bip39Seed, err = MnemonicToBIP39Seed(req.Mnemonic, "")
		if err != nil {
			return nil, err
		}
	}
	if len(bip39Seed) > 0 {
		seedKEK, err := DeriveBackupKEK(bip39Seed)
		if err != nil {
			return nil, err
		}
		wrapped, nonce, err := WrapBEK(seedKEK, slotSecret)
		if err != nil {
			return nil, err
		}
		manifest.KeySlots = append(manifest.KeySlots, KeySlot{
			Type:          SlotSeedHD,
			Policy:        manifest.SlotPolicy,
			WrappedBEKB64: EncodeB64(wrapped),
			NonceB64:      EncodeB64(nonce),
		})
	}

	// Sealed slots — one per recipient, any of which opens the archive.
	for i, recipientPub := range req.SealToPublicKeys {
		ephPub, wrappedS, nonceS, err := SealBEK(recipientPub, slotSecret)
		if err != nil {
			return nil, fmt.Errorf("seal to recipient %d: %w", i, err)
		}
		manifest.KeySlots = append(manifest.KeySlots, KeySlot{
			Type:            SlotSealedX25519,
			Policy:          manifest.SlotPolicy,
			WrappedBEKB64:   EncodeB64(wrappedS),
			NonceB64:        EncodeB64(nonceS),
			EphemeralPubB64: EncodeB64(ephPub),
		})
	}

	// The passphrase. Under OR it is another door; under AND it is the second
	// lock on every door there is.
	//
	// Writing a passphrase SLOT under AND would undo the whole thing — the slot
	// holds the payload key, so anyone with the passphrase alone would walk in
	// past the very requirement the archive claims to enforce. So under AND the
	// passphrase gets no slot at all. It only ever appears combined.
	if req.Passphrase != "" {
		params := DefaultArgon2Params()
		manifest.Argon2Params = &params
		salt, err := randomBytes(Argon2SaltLen)
		if err != nil {
			return nil, err
		}
		passKEK, err := DerivePassphraseKEK(req.Passphrase, salt, params)
		if err != nil {
			return nil, err
		}

		if requireAll {
			combined, err := CombineFactors(slotSecret, passKEK)
			if err != nil {
				return nil, err
			}
			wrappedAnd, nonceAnd, err := WrapBEK(combined, bek)
			if err != nil {
				return nil, err
			}
			manifest.AndWrappedBEKB64 = EncodeB64(wrappedAnd)
			manifest.AndNonceB64 = EncodeB64(nonceAnd)
			// The salt still has to travel, or the passphrase cannot be turned
			// back into the same key. It rides on a slot that unlocks nothing.
			manifest.KeySlots = append(manifest.KeySlots, KeySlot{
				Type:          SlotPassphrase,
				Policy:        PolicyAND,
				Argon2SaltB64: EncodeB64(salt),
			})
		} else {
			wrappedP, nonceP, err := WrapBEK(passKEK, bek)
			if err != nil {
				return nil, err
			}
			manifest.KeySlots = append(manifest.KeySlots, KeySlot{
				Type:          SlotPassphrase,
				Policy:        PolicyOR,
				WrappedBEKB64: EncodeB64(wrappedP),
				NonceB64:      EncodeB64(nonceP),
				Argon2SaltB64: EncodeB64(salt),
			})
		}
	}

	manifest.KeySlots = append(manifest.KeySlots, req.GuardianSlots...)

	arch := &ArchiveFile{Manifest: manifest, Ciphertext: ciphertext}
	raw, err := EncodeArchive(arch)
	if err != nil {
		return nil, err
	}

	return &ExportResult{
		Bytes:        raw,
		Manifest:     manifest,
		Size:         len(raw),
		Tiers:        tiers,
		SnapshotType: snapshotType,
	}, nil
}

// OpenArchive decrypts an .iab using the first matching key slot.
type OpenRequest struct {
	Mnemonic   string
	Passphrase string
	BIP39Seed  []byte
	// SealPrivateKey opens a sealed slot directly. It is not normally needed:
	// a mnemonic or seed derives the same key, so recovery from the phrase
	// alone works without the caller knowing sealing exists.
	SealPrivateKey []byte
}

func OpenArchive(data []byte, req OpenRequest) (*PayloadBundle, *Manifest, error) {
	arch, err := DecodeArchive(data)
	if err != nil {
		return nil, nil, err
	}
	if arch.Manifest.FormatVersion > FormatVersion {
		return nil, nil, fmt.Errorf("unsupported format_version %d", arch.Manifest.FormatVersion)
	}

	nonce, err := DecodeB64(arch.Manifest.PayloadNonceB64)
	if err != nil {
		return nil, nil, err
	}

	var bip39Seed []byte
	if len(req.BIP39Seed) > 0 {
		bip39Seed = req.BIP39Seed
	} else if req.Mnemonic != "" {
		bip39Seed, err = MnemonicToBIP39Seed(req.Mnemonic, "")
		if err != nil {
			return nil, nil, err
		}
	}

	// The sealing key comes from the same seed the phrase produces, so somebody
	// recovering with nothing but their words opens a sealed archive without
	// having to supply anything extra.
	// Read once, before anything is tried, because it changes what a slot
	// yielding a secret actually means.
	requireAll := arch.Manifest.SlotPolicy == PolicyAND
	if requireAll && req.Passphrase == "" {
		return nil, nil, fmt.Errorf("this archive requires a passphrase as well as a key, and none was given")
	}

	sealPriv := req.SealPrivateKey
	if len(sealPriv) == 0 && len(bip39Seed) > 0 {
		if priv, _, derr := DeriveSealKeypair(bip39Seed); derr == nil {
			sealPriv = priv
		}
	}

	var bek []byte
	var unwrapErr error
	for _, slot := range arch.Manifest.KeySlots {
		switch slot.Type {
		case SlotSealedX25519:
			if len(sealPriv) == 0 {
				continue
			}
			ephPub, err := DecodeB64(slot.EphemeralPubB64)
			if err != nil {
				continue
			}
			wrapped, err := DecodeB64(slot.WrappedBEKB64)
			if err != nil {
				continue
			}
			slotNonce, err := DecodeB64(slot.NonceB64)
			if err != nil {
				continue
			}
			// A slot meant for a different recipient fails its authentication
			// tag rather than yielding anything, so walking past it is safe —
			// that is what lets an archive carry one slot per owner without
			// saying which is whose.
			bek, unwrapErr = UnsealBEK(sealPriv, ephPub, wrapped, slotNonce)
		case SlotSeedHD:
			if len(bip39Seed) == 0 {
				continue
			}
			kek, err := DeriveBackupKEK(bip39Seed)
			if err != nil {
				unwrapErr = err
				continue
			}
			bek, unwrapErr = tryUnwrapSlot(kek, slot)
		case SlotPassphrase:
			// Under AND this slot carries only the salt and unlocks nothing.
			// Treating it as a way in is precisely the bypass AND exists to
			// prevent, so it is skipped rather than tried.
			if requireAll {
				continue
			}
			if req.Passphrase == "" || arch.Manifest.Argon2Params == nil {
				continue
			}
			salt, err := DecodeB64(slot.Argon2SaltB64)
			if err != nil {
				continue
			}
			kek, err := DerivePassphraseKEK(req.Passphrase, salt, *arch.Manifest.Argon2Params)
			if err != nil {
				continue
			}
			bek, unwrapErr = tryUnwrapSlot(kek, slot)
		default:
			continue
		}
		if bek != nil {
			break
		}
	}
	if bek == nil {
		if unwrapErr != nil {
			return nil, nil, fmt.Errorf("no key slot unlocked: %w", unwrapErr)
		}
		return nil, nil, fmt.Errorf("no key slot unlocked")
	}

	// Under AND, what came out of the slot is not the payload key — it is one
	// half. Without the passphrase the archive stays shut here, which is the
	// entire difference between saying AND and meaning it.
	if requireAll {
		combined, err := combineWithPassphrase(bek, req.Passphrase, &arch.Manifest)
		if err != nil {
			return nil, nil, err
		}
		wrapped, err := DecodeB64(arch.Manifest.AndWrappedBEKB64)
		if err != nil {
			return nil, nil, fmt.Errorf("this archive requires two factors but its second layer is unreadable: %w", err)
		}
		andNonce, err := DecodeB64(arch.Manifest.AndNonceB64)
		if err != nil {
			return nil, nil, fmt.Errorf("this archive requires two factors but its second layer is unreadable: %w", err)
		}
		if bek, err = UnwrapBEK(combined, wrapped, andNonce); err != nil {
			return nil, nil, fmt.Errorf("the passphrase did not open the second layer: %w", err)
		}
	}

	plain, err := DecryptPayload(bek, arch.Ciphertext, nonce)
	if err != nil {
		return nil, nil, err
	}
	bundle, err := DeserializePayloadBundle(plain)
	if err != nil {
		return nil, nil, err
	}
	if err := arch.Manifest.ValidateSections(bundle); err != nil {
		return nil, nil, fmt.Errorf("integrity check failed: %w", err)
	}
	return bundle, &arch.Manifest, nil
}

func tryUnwrapSlot(kek []byte, slot KeySlot) ([]byte, error) {
	wrapped, err := DecodeB64(slot.WrappedBEKB64)
	if err != nil {
		return nil, err
	}
	nonce, err := DecodeB64(slot.NonceB64)
	if err != nil {
		return nil, err
	}
	return UnwrapBEK(kek, wrapped, nonce)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// combineWithPassphrase joins the secret a slot yielded with the passphrase, to
// produce the key that opens an AND archive's second layer.
//
// The salt travels on the passphrase slot even though that slot unlocks
// nothing, because without it the same passphrase produces a different key and
// the archive is unopenable by anybody, including its owner.
func combineWithPassphrase(slotSecret []byte, passphrase string, manifest *Manifest) ([]byte, error) {
	if manifest.Argon2Params == nil {
		return nil, fmt.Errorf("this archive requires a passphrase but records no parameters for deriving it")
	}
	for _, slot := range manifest.KeySlots {
		if slot.Type != SlotPassphrase || slot.Argon2SaltB64 == "" {
			continue
		}
		salt, err := DecodeB64(slot.Argon2SaltB64)
		if err != nil {
			return nil, fmt.Errorf("this archive's passphrase salt is unreadable: %w", err)
		}
		passKEK, err := DerivePassphraseKEK(passphrase, salt, *manifest.Argon2Params)
		if err != nil {
			return nil, err
		}
		return CombineFactors(slotSecret, passKEK)
	}
	return nil, fmt.Errorf("this archive requires a passphrase but carries no salt to derive it with")
}
