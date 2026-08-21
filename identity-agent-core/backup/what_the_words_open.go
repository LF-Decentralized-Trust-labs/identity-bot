package backup

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/hkdf"
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
	// No check that the AID is set, deliberately.
	//
	// The manifest says an AID is "a label on the manifest, not something the
	// archive depends on, so its absence must not stop a backup" — an agent
	// exporting before an identity exists, or on a machine with no store, has
	// none to give. Requiring one here made a split backup impossible in
	// exactly those cases and turned a documented-optional label into
	// something load-bearing.
	//
	// A recovering machine reads this to know what it is about to become, and
	// an empty answer is worse than a filled one — but refusing to back up is
	// worse than both.
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

// PadEnvelope rounds an envelope up so its length stops describing its
// contents.
//
// AES-GCM does not pad, so the encrypted envelope is exactly as long as what
// went into it — and what goes into it is one wrap per combination of holders
// that can open it. Every shape from one-of-two upward therefore produced a
// distinct length, printed in the CLEARTEXT manifest, so anybody holding the
// file could read off how many holders an identity has and exactly how many
// are needed, without the words and without opening anything.
//
// Who the holders are stayed hidden, which was the part this envelope was
// built to protect. The threshold did not. Rounding to a bucket costs a few
// kilobytes and takes the shape away.
func PadEnvelope(plain []byte) []byte {
	const bucket = 16 << 10
	// A length prefix, so the padding can be removed exactly rather than by
	// guessing where the JSON ends.
	out := make([]byte, 4, ((len(plain)+4)/bucket+1)*bucket)
	binary.BigEndian.PutUint32(out, uint32(len(plain)))
	out = append(out, plain...)
	for len(out) < cap(out) {
		out = append(out, 0)
	}
	return out
}

// UnpadEnvelope recovers what PadEnvelope wrapped.
func UnpadEnvelope(padded []byte) ([]byte, error) {
	if len(padded) < 4 {
		return nil, fmt.Errorf("this envelope is too short to be one")
	}
	n := binary.BigEndian.Uint32(padded[:4])
	if int(n)+4 > len(padded) {
		return nil, fmt.Errorf("this envelope says it is longer than it is")
	}
	return padded[4 : 4+n], nil
}

// DeriveBootstrapKEKFrom derives the key that opens the bootstrap envelope,
// from whichever first factor this archive uses.
//
// Domain-separated from the backup KEK so that the key the words produce for
// this envelope is not the key they produce for anything else. Both come from
// the same seed, so this is not a second secret to remember — it is the same
// answer to the same question, kept from being reused across two purposes.
//
// Hygiene rather than load-bearing, and worth saying so: pointing this at the
// backup KEK's own salt and info fails no test here, because the two
// ciphertexts carry independent random nonces and reaching either key needs
// the seed regardless. It stays because a key that encrypts two different
// things is a thing to avoid on principle, not because something breaks.
func DeriveBootstrapKEKFrom(firstFactor []byte) []byte {
	r := hkdf.New(sha256.New, firstFactor,
		[]byte("identity-agent-bootstrap-salt-v1"),
		[]byte("identity-agent/bootstrap-kek/v1"))
	out := make([]byte, 32)
	r.Read(out)
	return out
}
