package recovery

import (
	"encoding/json"
	"fmt"

	"identity-agent-core/backup"
	"identity-agent-core/store"
)

// OpenRequest mirrors backup.OpenRequest for archive decryption.
type OpenRequest struct {
	Mnemonic   string
	Passphrase string
	BIP39Seed  []byte
}

// RestoredPayload is the decrypted, integrity-checked content of a .iab archive.
type RestoredPayload struct {
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
	bundle, manifest, err := backup.OpenArchive(data, backup.OpenRequest{
		Mnemonic:   req.Mnemonic,
		Passphrase: req.Passphrase,
		BIP39Seed:  req.BIP39Seed,
	})
	if err != nil {
		return nil, fmt.Errorf("archive open failed: %w", err)
	}

	out := &RestoredPayload{
		Manifest: *manifest,
		Bundle:   bundle,
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
