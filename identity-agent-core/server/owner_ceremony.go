package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Spreading control of an identity across more than one party.
//
// The identity exists and works throughout. What changes is who controls it:
// the key set grows, the threshold rises, and the owner seals are rewritten —
// in one rotation, keeping the identifier. An identity that changed identifier
// when control moved would lose every relationship it had, which is the thing
// the whole ownership design exists to prevent.
//
// The obvious case is a group taking joint control of something one of them
// created. It is not the only one: spreading control of your own identity so
// that recovery does not depend on a single key is the same operation, and so is
// handing an identity over entirely. Nothing here knows which it is doing.
//
// It is deliberately NOT part of founding. One party creates an identity and it
// works immediately; bringing others in is a separate, later, unhurried step. A
// ceremony that had to complete first would make founding wait on everybody's
// diary.
//
// NO KEY MATERIAL CROSSES THE WIRE. Each incoming party's agent derives a key
// on their own device and sends the public half. What this collects is a list of
// public keys and a number.

// ceremonyState is where a ceremony has got to.
const (
	ceremonyCollecting = "collecting"
	ceremonyApplied    = "applied"
	ceremonyFailed     = "failed"
	ceremonyAbandoned  = "abandoned"
)

// OwnerCeremony is one attempt to change who controls an identity.
type OwnerCeremony struct {
	ID string `json:"id"`
	// Threshold is how many of the resulting owners must sign afterwards.
	Threshold int `json:"threshold"`
	// OwnPublicKey and OwnNextPublicKey are the identity's own rotation keys,
	// supplied by whoever starts the ceremony.
	//
	// They are not derived here, because this agent does not hold the seed they
	// come from — every rotation in this system is driven by the device that
	// does, which sends only public halves. A rotation must also include a key
	// the previous event committed to, so these are not free choices: they are
	// the pre-rotated key and its successor.
	OwnPublicKey     string `json:"org_public_key,omitempty"`
	OwnNextPublicKey string `json:"org_next_public_key,omitempty"`
	// Invited is one entry per party being brought in, in the order they were
	// named, so a half-finished ceremony can say who is still missing rather
	// than only how many.
	Invited []CeremonyInvitee `json:"invited"`
	Status  string            `json:"status"`
	// Detail explains a failure in words somebody can act on. A ceremony that
	// failed and does not say why leaves everyone unsure whether control
	// actually changed.
	Detail    string    `json:"detail,omitempty"`
	StartedAt time.Time `json:"started_at"`
	AppliedAt time.Time `json:"applied_at,omitempty"`
	// RotationSAID is the event that made it real, so the ceremony record and
	// the key log can be reconciled by anyone reading both.
	RotationSAID string `json:"rotation_said,omitempty"`
}

// CeremonyInvitee is one party being made an owner.
type CeremonyInvitee struct {
	Name string `json:"name"`
	// Token is the invite they redeem, and InviteURL is what becomes their QR
	// code. One each: a shared code could be redeemed twice by the same person
	// and leave a place at the table unfilled.
	Token     string `json:"token"`
	InviteURL string `json:"invite_url"`

	// Filled in when they accept, from their own device. Both halves are
	// public: the key they will sign with, and the one they commit to rotating
	// into. A key set that commits to no successors can never rotate again, so
	// an identity that took on owners without collecting these would have made
	// its last ownership change without knowing it.
	PairwiseAID   string    `json:"pairwise_aid,omitempty"`
	PublicKey     string    `json:"public_key,omitempty"`
	NextPublicKey string    `json:"next_public_key,omitempty"`
	AcceptedAt    time.Time `json:"accepted_at,omitempty"`
}

// Accepted reports whether this person has taken part yet.
func (c CeremonyInvitee) Accepted() bool {
	return c.PairwiseAID != "" && c.PublicKey != "" && c.NextPublicKey != ""
}

// Outstanding lists who has not accepted yet.
func (c *OwnerCeremony) Outstanding() []string {
	var waiting []string
	for _, invitee := range c.Invited {
		if !invitee.Accepted() {
			name := invitee.Name
			if name == "" {
				name = "an unnamed invitee"
			}
			waiting = append(waiting, name)
		}
	}
	return waiting
}

// ceremonyFile holds the one ceremony in progress.
//
// One at a time, deliberately. Two overlapping ceremonies would each rotate
// from a key set the other had already replaced, so the second would be built
// on a state that no longer exists — and the failure would appear at the end,
// after everybody had already signed.
const ceremonyFile = "owner_ceremony.json"

var ceremonyMu sync.Mutex

func (s *CoreServer) ceremonyPath() string {
	return filepath.Join(s.DataDir, ceremonyFile)
}

// loadCeremony reads the ceremony in progress, or nil. Callers hold the lock.
func (s *CoreServer) loadCeremony() (*OwnerCeremony, error) {
	raw, err := os.ReadFile(s.ceremonyPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c OwnerCeremony
	if jerr := json.Unmarshal(raw, &c); jerr != nil {
		return nil, fmt.Errorf("the ceremony record is unreadable: %w", jerr)
	}
	return &c, nil
}

// saveCeremony records it. Callers hold the lock.
func (s *CoreServer) saveCeremony(c *OwnerCeremony) error {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	path := s.ceremonyPath()
	tmp := path + ".tmp"
	// Written beside and renamed. A half-written ceremony would read as one
	// nobody had joined, and the people who had already accepted would have to
	// do it again with no way to know they needed to.
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// recordAcceptance stores one invitee's key against their token.
//
// Returns the ceremony when this acceptance completed it, so the caller knows
// to rotate. Returns nil when the token belongs to no ceremony, which is the
// ordinary case for an invite that is not part of one and is not an error.
func (s *CoreServer) recordAcceptance(token, pairwiseAID, publicKey, nextPublicKey string) (*OwnerCeremony, bool, error) {
	ceremonyMu.Lock()
	defer ceremonyMu.Unlock()

	c, err := s.loadCeremony()
	if err != nil || c == nil {
		return nil, false, err
	}
	if c.Status != ceremonyCollecting {
		return nil, false, nil
	}

	found := false
	for i := range c.Invited {
		if c.Invited[i].Token != token {
			continue
		}
		found = true
		if c.Invited[i].Accepted() {
			// Already done. Not an error — a second scan of the same code is a
			// person checking it worked, and it must not overwrite the key they
			// already committed to.
			return nil, false, nil
		}
		c.Invited[i].PairwiseAID = pairwiseAID
		c.Invited[i].PublicKey = publicKey
		c.Invited[i].NextPublicKey = nextPublicKey
		c.Invited[i].AcceptedAt = time.Now().UTC()
		break
	}
	if !found {
		return nil, false, nil
	}
	if err := s.saveCeremony(c); err != nil {
		return nil, false, err
	}

	if len(c.Outstanding()) > 0 {
		return c, false, nil
	}
	return c, true, nil
}

// finishCeremony records the outcome of the rotation.
func (s *CoreServer) finishCeremony(status, detail, rotationSAID string) error {
	ceremonyMu.Lock()
	defer ceremonyMu.Unlock()

	c, err := s.loadCeremony()
	if err != nil || c == nil {
		return err
	}
	c.Status = status
	c.Detail = detail
	c.RotationSAID = rotationSAID
	if status == ceremonyApplied {
		c.AppliedAt = time.Now().UTC()
	}
	return s.saveCeremony(c)
}
