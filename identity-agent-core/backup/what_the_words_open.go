package backup

import (
	"encoding/json"
	"fmt"
)

// BootstrapSection is where the words-openable envelope lives in a payload.
const BootstrapSection = "bootstrap"

// WhatTheWordsOpen is everything the recovery phrase alone gives access to.
//
// It is a CLOSED LIST, and it is the only allow list in this package that
// should be one.
//
// Everywhere else, backup moved away from naming what to include, because an
// allow list fails silently in the direction that matters: something new
// appears on the device, nobody adds it, every backup reports success, and the
// gap is measured on the day of the restore. Here the risk runs the other way.
// Anything placed in this envelope becomes openable by the words alone, which
// is exactly the property the rest of this design exists to remove — so a
// field added here without thought quietly returns private data to a stolen
// phrase.
//
// The test beside this file enumerates these fields and fails when the set
// changes. That is deliberate: adding one should require somebody to say, in
// writing, why a thief holding this identity's backup and its words may read
// the new thing.
//
// The rule for what belongs: public keys, identifiers already published in the
// key event log, and policy. Nothing that is a secret, and nothing that
// describes who this identity knows — a social graph is precisely what an
// owner is harmed by leaking, which is why the contact list is NOT here and
// why the holders check a recovery on their own side rather than the
// recovering machine challenging contacts it would first have to be told
// about.
type WhatTheWordsOpen struct {
	// IdentityAID is which identity this backup is of. Already public: it is
	// the name every witness and every counterparty knows it by.
	IdentityAID string `json:"identity_aid"`

	// Split is the threshold and who holds a share — their identifiers, their
	// public keys and where to reach them. A recovering machine cannot ask for
	// shares without knowing who to ask, so this has to be readable before any
	// share is gathered.
	Split HowTheWayInIsSplit `json:"split"`

	// SealedShares are each holder's share, sealed to that holder's own key.
	// Readable here, useless here: opening one needs a private key this
	// archive never contained and the writing agent never had.
	SealedShares []SealedShare `json:"sealed_shares"`

	// SubsetWraps are the main key wrapped under each combination of shares
	// that can open it. Useless without k shares, by construction.
	SubsetWraps []SubsetWrap `json:"subset_wraps"`

	// DuressPolicy is what this identity chose about being coerced.
	//
	// It must be here rather than in the main envelope, and the reason is the
	// whole of gate three: a machine recovering an identity has nothing of its
	// own to read, so a policy that travels only in the part which needs
	// shares to open cannot be consulted before deciding whether to release
	// them. It has already been absent from every archive once, through a
	// tier nothing requested, and the gate then found nothing and passed.
	DuressPolicy json.RawMessage `json:"duress_policy,omitempty"`

	// AuthenticatorPublicKeys are the public halves of what this identity
	// enrolled to prove who it is. Public by definition — the private halves
	// are what does the proving, and they are not here.
	AuthenticatorPublicKeys []string `json:"authenticator_public_keys,omitempty"`
}

// bootstrapFields is the closed list, written out so that changing the struct
// changes a value somebody has to look at.
//
// Kept beside the type rather than derived from it, because a guard derived
// from the thing it guards agrees with itself by construction.
var bootstrapFields = []string{
	"identity_aid",
	"split",
	"sealed_shares",
	"subset_wraps",
	"duress_policy",
	"authenticator_public_keys",
}

// Validate refuses a bootstrap envelope that cannot do its job.
func (w WhatTheWordsOpen) Validate() error {
	if w.IdentityAID == "" {
		return fmt.Errorf("the bootstrap envelope does not say which identity this is")
	}
	if err := w.Split.Validate(); err != nil {
		return err
	}
	if len(w.SealedShares) != len(w.Split.Holders) {
		return fmt.Errorf(
			"this backup names %d holders and carries %d shares, so at least one holder "+
				"could never take part", len(w.Split.Holders), len(w.SealedShares))
	}
	seen := map[string]bool{}
	for _, s := range w.SealedShares {
		seen[s.HolderID] = true
	}
	for _, h := range w.Split.Holders {
		if !seen[h.ID] {
			return fmt.Errorf("holder %s has no share in this backup", h.ID)
		}
	}
	if len(w.SubsetWraps) == 0 {
		return fmt.Errorf("this backup carries no way to reassemble its key")
	}
	return nil
}
