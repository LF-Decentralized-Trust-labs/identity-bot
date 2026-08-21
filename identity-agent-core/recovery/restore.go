package recovery

import (
	"encoding/json"
	"errors"
	"fmt"

	"identity-agent-core/backup"
	"identity-agent-core/store"
)

// OpenRequest mirrors backup.OpenRequest for archive decryption.
type OpenRequest struct {
	Mnemonic   string
	Passphrase string
	BIP39Seed  []byte
	// ExpectedWriterKey is the signing key recorded when the machine that
	// wrote this archive was paired. Without it, a machine-signed archive
	// proves only that its writer can sign their own work.
	ExpectedWriterKey []byte
	// RequireAttribution refuses an archive that says nothing about who wrote
	// it.
	//
	// OFF by default, and that default is a compromise rather than a
	// preference. Every archive written before origin was recorded is
	// unattributed, and so is every archive a paired machine writes today —
	// those machines hold the owner's public key and no signing key of their
	// own, so they cannot say who they are yet. Refusing them would break the
	// one backup a paired computer can make, which is worse than the hole it
	// would close, because a failed recovery is a certainty and a substituted
	// archive is a risk.
	//
	// It flips to on once machines carry a signing key, and a caller that
	// knows it is dealing with modern archives can turn it on today. Either
	// way the payload says which it got, so a screen can tell somebody that
	// this archive could not prove where it came from.
	RequireAttribution bool
	// Shares are what the holders returned, keyed by holder id.
	//
	// An archive protected by shares does not open without enough of them, so
	// this has to reach all the way down. Leaving it off meant every path
	// above backup — verifying, starting a session, activating — refused a
	// split archive and reported it as a failure, which made the session, the
	// cancel window and the duress gate unreachable for exactly the archives
	// this design was built for.
	Shares map[string][]byte
}

// RestoredPayload is the decrypted, integrity-checked content of a .iab archive.
type RestoredPayload struct {
	// WriterUnknown says this archive carried nothing about who wrote it, so
	// opening it proved only that it was encrypted to this owner. Anybody can
	// encrypt to a public key, so a screen should say so.
	WriterUnknown bool

	Manifest  backup.Manifest
	Bundle    *backup.PayloadBundle
	Identity  *store.IdentityState
	Contacts  []ContactPairwiseExpectation
	KelEvents []store.EventRecord
}

// ContactPairwiseExpectation extends contact records with HD pairwise expectations.
type ContactPairwiseExpectation struct {
	store.ContactRecord
	PairwisePublicKey string `json:"pairwise_public_key,omitempty"`
}

// RestoreFromArchive decrypts a .iab with the seed, validates Blake3 section digests,
// and parses identity/contacts payloads.
func RestoreFromArchive(data []byte, req OpenRequest) (*RestoredPayload, error) {
	// Who wrote this, before anything in it is believed.
	//
	// Opening an archive proves it was encrypted to this owner and nothing
	// more, because sealing needs only a public key and public keys are
	// public. A restore then writes every file the archive carries back to its
	// path and replaces contacts, credentials and settings — so a substituted
	// archive is attacker-chosen content written into somebody's agent, and
	// the realistic route is a destination rather than a person being tricked.
	//
	// Checked before the archive is opened, so a forged one is refused without
	// its contents ever being unpacked.
	if err := checkWhoWroteIt(data, req); err != nil {
		return nil, err
	}

	bundle, manifest, err := backup.OpenArchive(data, backup.OpenRequest{
		Mnemonic:   req.Mnemonic,
		Passphrase: req.Passphrase,
		BIP39Seed:  req.BIP39Seed,
		Shares:     req.Shares,
	})
	if err != nil {
		// Needing shares is not this archive failing to open, and wrapping it
		// as one produced "archive open failed: the recovery words are right"
		// — a sentence that contradicts itself, on the screen of somebody in
		// the middle of losing their identity. It travels untouched so the
		// layers above can act on it.
		var needs *backup.ErrNeedsShares
		if errors.As(err, &needs) {
			return nil, err
		}
		return nil, fmt.Errorf("archive open failed: %w", err)
	}

	// An archive that cannot restore on its own is refused, loudly.
	//
	// A delta carries only what changed since the last backup. Restoring one
	// alone gives an identity plus whatever happened to change recently, and
	// silently omits everything that did not — contacts, credentials, files —
	// which is indistinguishable from a complete restore from the outside.
	//
	// Refusing is the whole point. Somebody who is told their archive is a
	// partial one can go and find the full snapshot it extends. Somebody handed
	// a quietly incomplete restore finds out months later, if ever.
	if !manifest.SelfSufficient && manifest.SnapshotType == backup.SnapshotDelta {
		return nil, fmt.Errorf(
			"this archive is an incremental backup and cannot be restored on its own: "+
				"it holds only what changed, taken %s. Restore the most recent FULL "+
				"backup instead", manifest.CreatedAt)
	}

	out := &RestoredPayload{
		Manifest:      *manifest,
		Bundle:        bundle,
		WriterUnknown: manifest.WrittenBy == "",
	}

	if raw, ok := bundle.Sections["identity_state"]; ok && len(raw) > 0 {
		var id store.IdentityState
		if err := json.Unmarshal(raw, &id); err != nil {
			return nil, fmt.Errorf("identity_state parse: %w", err)
		}
		out.Identity = &id
	}

	if raw, ok := bundle.Sections["kel_events"]; ok && len(raw) > 0 {
		if err := json.Unmarshal(raw, &out.KelEvents); err != nil {
			return nil, fmt.Errorf("kel_events parse: %w", err)
		}
	}

	if raw, ok := bundle.Sections["contacts"]; ok && len(raw) > 0 {
		if err := json.Unmarshal(raw, &out.Contacts); err != nil {
			return nil, fmt.Errorf("contacts parse: %w", err)
		}
	}

	return out, nil
}

// BIP39Seed resolves the BIP39 seed bytes from an open request.
func BIP39Seed(req OpenRequest) ([]byte, error) {
	if len(req.BIP39Seed) > 0 {
		return req.BIP39Seed, nil
	}
	if req.Mnemonic == "" {
		return nil, fmt.Errorf("mnemonic or bip39 seed required")
	}
	return backup.MnemonicToBIP39Seed(req.Mnemonic, "")
}

// checkWhoWroteIt refuses an archive whose origin cannot be established.
func checkWhoWroteIt(data []byte, req OpenRequest) error {
	arch, err := backup.DecodeArchive(data)
	if err != nil {
		return fmt.Errorf("archive open failed: %w", err)
	}
	seed := req.BIP39Seed
	if len(seed) == 0 && req.Mnemonic != "" {
		if seed, err = backup.MnemonicToBIP39Seed(req.Mnemonic, ""); err != nil {
			return err
		}
	}

	err = backup.CheckWhoWroteIt(arch, seed, req.ExpectedWriterKey)
	if errors.Is(err, backup.ErrArchiveUnattributed) && !req.RequireAttribution {
		// Allowed, and recorded on the payload so it is not silent. A wrong
		// mark is always refused — only a MISSING one is tolerated, and only
		// while archives that cannot carry one still exist.
		return nil
	}
	return err
}
