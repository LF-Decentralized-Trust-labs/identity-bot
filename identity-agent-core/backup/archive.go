package backup

import (
	"crypto/rand"
	"encoding/json"
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

	// Split, when it names holders, is what makes this archive need the words
	// PLUS shares. Leaving it empty writes an archive of the older shape,
	// openable from a key slot, which is what every existing archive is.
	Split HowTheWayInIsSplit
	// DuressPolicy and AuthenticatorPublicKeys ride in the bootstrap envelope,
	// where a machine with nothing of its own can read them before deciding
	// whether to ask for shares.
	DuressPolicy            []byte
	AuthenticatorPublicKeys []string
}

// ExportResult describes a completed export.
type ExportResult struct {
	Bytes        []byte
	Manifest     Manifest
	Size         int
	Tiers        []string
	SnapshotType string

	// VerifiedAt is set only once the archive has been reopened and its
	// contents checked. An archive that was never verified leaves this empty,
	// so "we made a backup" and "we made a backup that opens" stay separable.
	VerifiedAt string
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
	// Only a full snapshot holds everything. See Manifest.SelfSufficient.
	manifest.SelfSufficient = snapshotType == SnapshotFull
	if req.SlotPolicy != "" {
		manifest.SlotPolicy = req.SlotPolicy
	}
	// A passphrase makes an archive HARDER to open, never easier.
	//
	// Under the OR policy a passphrase slot wraps the payload key itself, so
	// the passphrase alone opens the archive — a second key, and a far weaker
	// one than twenty-four words, offline-guessable by anybody holding the
	// file. No caller outside this package's tests ever set a policy, and the
	// default is OR, so every archive any route could produce was in the mode
	// this file's own comments describe as making things easier.
	//
	// Supplying a passphrase now means BOTH factors are required. That is what
	// somebody adding one believes they are getting, and it is the only reading
	// under which adding a secret is not a downgrade.
	if req.Passphrase != "" && req.SlotPolicy == "" {
		manifest.SlotPolicy = PolicyAND
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

	// An archive whose way in is split across holders.
	//
	// The body key goes into the shares and NOWHERE ELSE — no seed slot, no
	// passphrase slot, no sealed slot. That is the whole change: leave a slot
	// wrapping it and the recovery words open the body directly, and every
	// share becomes decoration. So this returns here rather than falling
	// through to the slot-writing below.
	//
	// What the words do open is the bootstrap envelope: who holds a share and
	// where to reach them, the duress policy a blank machine must be able to
	// consult before asking anyone, and the wraps that k shares reassemble.
	if len(req.Split.Holders) > 0 {
		// The other ways into an archive are refused rather than dropped.
		//
		// The split path returns before any slot is written, so a caller that
		// asked for a sealed recipient, a guardian slot or a passphrase got an
		// archive where none of them exist — and no error. The export path
		// always passes sealed recipients, so wiring a split into it would
		// have silently produced archives that every destination meant to open
		// them could not.
		//
		// Combining them is a real thing to build and is not built: a sealed
		// slot would have to become one share among the rest rather than a
		// second independent way in, which is the whole rule this design
		// rests on. Until then, saying so beats quietly ignoring it.
		if len(req.SealToPublicKeys) > 0 || len(req.GuardianSlots) > 0 || req.Passphrase != "" {
			return nil, fmt.Errorf(
				"this backup is protected by shares, which cannot yet be combined with " +
					"a passphrase, a guardian slot, or sealing to another recipient")
		}
		if req.Split.OnlyShareIsAPassphrase() {
			// An attacker holds the file and can try every short secret
			// offline, without asking anybody and without anything noticing.
			// As the only share that is a way in rather than a share.
			return nil, fmt.Errorf(
				"a passphrase cannot be the only thing protecting this backup besides the " +
					"recovery words: add a device or a person")
		}
		// A split archive needs the words at the moment it is written,
		// because the key each combination of shares produces is combined
		// with the key the words derive. That makes it incompatible with the
		// sealed-export path, where a machine writes a backup for an identity
		// whose seed it has never been told — and saying so here beats
		// producing an archive that quietly is not split.
		seed := req.BIP39Seed
		if len(seed) == 0 && req.Mnemonic != "" {
			seed, err = MnemonicToBIP39Seed(req.Mnemonic, "")
			if err != nil {
				return nil, err
			}
		}
		if len(seed) == 0 {
			return nil, fmt.Errorf(
				"this backup is protected by shares as well as the recovery words, so it " +
					"cannot be written by a machine that has never been told them")
		}
		seedKEK, err := DeriveBackupKEK(seed)
		if err != nil {
			return nil, err
		}
		sealedShares, wraps, err := SplitTheWayIn(bek, seedKEK, req.Split)
		if err != nil {
			return nil, err
		}
		env := WhatTheWordsOpen{
			IdentityAID:             manifest.IdentityAID,
			Split:                   req.Split,
			SealedShares:            sealedShares,
			SubsetWraps:             wraps,
			DuressPolicy:            req.DuressPolicy,
			AuthenticatorPublicKeys: req.AuthenticatorPublicKeys,
		}
		if err := env.Validate(); err != nil {
			return nil, err
		}
		envPlain, err := json.Marshal(env)
		if err != nil {
			return nil, err
		}
		bootKEK, err := DeriveBootstrapKEK(seed)
		if err != nil {
			return nil, err
		}
		envCipher, envNonce, err := EncryptPayload(bootKEK, PadEnvelope(envPlain))
		if err != nil {
			return nil, err
		}
		manifest.BootstrapB64 = EncodeB64(envCipher)
		manifest.BootstrapNonceB64 = EncodeB64(envNonce)
		// Stated rather than relied upon: returning here is what actually
		// keeps slots off a split archive, since the slot-writing below is
		// never reached. Removing the return DOES fail a test — the one that
		// inspects a finished archive and refuses to find a slot in it.
		manifest.KeySlots = nil
		manifest.SlotPolicy = ""

		return finishArchive(manifest, ciphertext, tiers, snapshotType)
	}

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

	return finishArchive(manifest, ciphertext, tiers, snapshotType)
}

func finishArchive(manifest Manifest, ciphertext []byte, tiers []string, snapshotType string) (*ExportResult, error) {
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
	// Shares are what holders returned, keyed by holder id. Needed only for an
	// archive that was written with a split; ignored otherwise.
	Shares map[string][]byte
}

// ErrNeedsShares says the recovery words were right and are not enough.
//
// It is a distinct error rather than a general refusal because it is the one
// thing somebody in the middle of a recovery has to be told plainly, and
// because it is not a failure — it is the design working. What it carries is
// what a screen needs to say next: who to ask, and how many of them.
type ErrNeedsShares struct {
	Bootstrap *WhatTheWordsOpen
	Gathered  int
}

func (e *ErrNeedsShares) Error() string {
	return fmt.Sprintf(
		"the recovery words are right; this backup also needs %d of %d shares, and %d have been gathered",
		e.Bootstrap.Split.Needed, len(e.Bootstrap.Split.Holders), e.Gathered)
}

// OpenBootstrap opens the envelope the recovery words alone open.
//
// This is the whole of what a stolen phrase now gets: who holds a share and
// where to reach them, the duress policy, and wraps that are useless without
// k shares. A machine recovering an identity reads this FIRST, because it has
// nothing of its own to tell it who to ask.
//
// An archive written before shares existed has no such envelope, and that
// absence is not an error — it is how an old archive says its body can still
// be opened from a key slot.
func OpenBootstrap(data []byte, req OpenRequest) (*WhatTheWordsOpen, *Manifest, error) {
	arch, err := DecodeArchive(data)
	if err != nil {
		return nil, nil, err
	}
	if arch.Manifest.BootstrapB64 == "" {
		return nil, &arch.Manifest, nil
	}
	seed, err := seedFrom(req)
	if err != nil {
		return nil, &arch.Manifest, err
	}
	env, err := openBootstrapWith(seed, &arch.Manifest)
	if err != nil {
		return nil, &arch.Manifest, err
	}
	return env, &arch.Manifest, nil
}

func seedFrom(req OpenRequest) ([]byte, error) {
	if len(req.BIP39Seed) > 0 {
		return req.BIP39Seed, nil
	}
	if req.Mnemonic == "" {
		return nil, fmt.Errorf("no recovery words were given")
	}
	return MnemonicToBIP39Seed(req.Mnemonic, "")
}

func openBootstrapWith(seed []byte, manifest *Manifest) (*WhatTheWordsOpen, error) {
	bootKEK, err := DeriveBootstrapKEK(seed)
	if err != nil {
		return nil, err
	}
	cipher, err := DecodeB64(manifest.BootstrapB64)
	if err != nil {
		return nil, fmt.Errorf("read the envelope: %w", err)
	}
	nonce, err := DecodeB64(manifest.BootstrapNonceB64)
	if err != nil {
		return nil, fmt.Errorf("read the envelope: %w", err)
	}
	plain, err := DecryptPayload(bootKEK, cipher, nonce)
	if err != nil {
		// The same message a wrong phrase has always produced. A phrase that
		// opens no envelope and a phrase that opens the wrong identity are
		// both "these words do not open this backup".
		return nil, fmt.Errorf("those words do not open this backup")
	}
	unpadded, err := UnpadEnvelope(plain)
	if err != nil {
		return nil, fmt.Errorf("this backup's envelope could not be read: %w", err)
	}
	var env WhatTheWordsOpen
	if err := json.Unmarshal(unpadded, &env); err != nil {
		return nil, fmt.Errorf("this backup's envelope could not be read: %w", err)
	}
	return &env, nil
}

func OpenArchive(data []byte, req OpenRequest) (*PayloadBundle, *Manifest, error) {
	arch, err := DecodeArchive(data)
	if err != nil {
		return nil, nil, err
	}

	// Before anything else, including the split path below. This used to sit
	// after it, so an archive from a future version reported "you need more
	// shares" rather than "this build cannot read this", and somebody would
	// have gone looking for holders instead of an update.
	if arch.Manifest.FormatVersion > FormatVersion {
		return nil, &arch.Manifest, fmt.Errorf(
			"this backup was made by a newer version of the software (format %d, this "+
				"build understands %d) — update the software and try again",
			arch.Manifest.FormatVersion, FormatVersion)
	}

	// An archive whose way in is split across holders. The words open the
	// envelope; the body needs k shares, and there is no key slot holding the
	// body key — that is what makes the shares load-bearing rather than
	// decorative.
	if arch.Manifest.BootstrapB64 != "" {
		seed, err := seedFrom(req)
		if err != nil {
			return nil, &arch.Manifest, err
		}
		env, err := openBootstrapWith(seed, &arch.Manifest)
		if err != nil {
			return nil, &arch.Manifest, err
		}
		seedKEK, err := DeriveBackupKEK(seed)
		if err != nil {
			return nil, &arch.Manifest, err
		}
		bek, err := ReassembleTheWayIn(seedKEK, req.Shares, env.SubsetWraps)
		if err != nil {
			// Enough shares that did not work is a DIFFERENT thing from too
			// few, and saying "you need 2 of 3 and have 3" is both false and
			// hides the one condition the owner most needs told — that a
			// holder handed back something wrong.
			if len(req.Shares) >= env.Split.Needed {
				return nil, &arch.Manifest, fmt.Errorf(
					"%d share(s) came back, which is enough, and they do not open this "+
						"backup — at least one holder returned something that is not its share",
					len(req.Shares))
			}
			return nil, &arch.Manifest, &ErrNeedsShares{
				Bootstrap: env, Gathered: len(req.Shares),
			}
		}
		bundle, err := decryptBody(bek, arch)
		if err != nil {
			return nil, &arch.Manifest, err
		}
		return bundle, &arch.Manifest, nil
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

// decryptBody opens the main envelope and checks it against the manifest.
//
// The same integrity check the slot path performs, kept in one place so that
// the split path cannot quietly skip it. An archive that decrypts and does not
// match its own manifest is a partial restore waiting to be mistaken for a
// whole one.
func decryptBody(bek []byte, arch *ArchiveFile) (*PayloadBundle, error) {
	nonce, err := DecodeB64(arch.Manifest.PayloadNonceB64)
	if err != nil {
		return nil, err
	}
	plain, err := DecryptPayload(bek, arch.Ciphertext, nonce)
	if err != nil {
		return nil, err
	}
	bundle, err := DeserializePayloadBundle(plain)
	if err != nil {
		return nil, err
	}
	if err := arch.Manifest.ValidateSections(bundle); err != nil {
		return nil, fmt.Errorf("integrity check failed: %w", err)
	}
	return bundle, nil
}
