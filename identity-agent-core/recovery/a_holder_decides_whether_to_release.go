package recovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"identity-agent-core/backup"
)

// Holding somebody else's share, and deciding whether to hand it back.
//
// This is the half of the design that makes gates two and three govern the
// data rather than only this software. Somebody with the archive and the
// recovery words never runs our code, so a check performed by the recovering
// machine protects an honest person from a mistake and nothing more. A check
// performed HERE — on a machine the attacker does not control, holding a key
// they cannot obtain — is the only kind that binds them.
//
// THE HOLDER IS THE CLOCK, and that is the point of this file.
//
// A waiting period is only a protection if the person waiting cannot skip it.
// If the request said when the recovery began, an attacker would say it began
// last week. So the first time a holder is asked for a share, it writes down
// when that was, and it refuses until the wait has passed SINCE THEN. The
// attacker cannot move that clock forward because it is not theirs.
//
// THE POLICY IS THE HOLDER'S COPY, not the requester's.
//
// The duress policy travels in the bootstrap envelope so a blank machine can
// read it — but the requester holds that envelope, and anything they hold they
// can strip. So a holder keeps its own copy, given when it agreed to hold a
// share, and enforces that. What arrives in a request is never what decides.
//
// WHAT A HOLDER CANNOT CHECK, said plainly because pretending otherwise would
// be worse than not checking: it cannot verify how well authenticated somebody
// was on a machine it does not control. A self-reported level is a number the
// attacker chose. So authentication is enforced where it can be — by a person
// deciding, where the holder is a person's agent — and the level a request
// carries is recorded, never trusted.

// Holding is a share this machine agreed to hold for somebody else's identity.
type Holding struct {
	// IdentityAID is whose identity this protects. For a recovery witness this
	// is a pairwise identifier created for this relationship alone, so holding
	// a share does not tell this machine who the person is.
	IdentityAID string `json:"identity_aid"`
	// HolderID is how the archive names this holder.
	HolderID string `json:"holder_id"`
	// PrivateKeyB64 opens the sealed shares addressed to this holder. It never
	// leaves here, and it is why an archive plus the words is not enough.
	PrivateKeyB64 string `json:"private_key_b64"`
	// Policy is what this holder promised to enforce, recorded when it agreed
	// rather than read from whoever asks.
	Policy HoldingPolicy `json:"policy"`
}

// HoldingPolicy is what a holder enforces before releasing.
type HoldingPolicy struct {
	// WaitHours is how long after the FIRST request a share may be released.
	// Zero means release without waiting, which is a real choice and not a
	// default.
	WaitHours int `json:"wait_hours"`
	// RequireApproval means a person must say yes. Where the holder is
	// somebody's agent this is the strong answer to gate three: a human sees
	// that a request is wrong in a way no timer can.
	RequireApproval bool `json:"require_approval"`
}

// AskRecord is what this holder remembers about being asked.
//
// It is kept whatever the outcome, and that is deliberate: the record of
// having been asked is the thing that tells an owner somebody tried, and a
// refusal that leaves no trace is a refusal nobody learns from.
type AskRecord struct {
	IdentityAID string `json:"identity_aid"`
	// FirstAskedAt is the clock. Written once and never moved.
	FirstAskedAt string `json:"first_asked_at"`
	Times        int    `json:"times"`
	LastAskedAt  string `json:"last_asked_at"`
	Approved     bool   `json:"approved"`
	ApprovedAt   string `json:"approved_at,omitempty"`
	ReleasedAt   string `json:"released_at,omitempty"`
}

// ErrHeldForWait says a share exists and is not being released yet.
type ErrHeldForWait struct {
	Until     time.Time
	Remaining time.Duration
}

func (e *ErrHeldForWait) Error() string {
	return fmt.Sprintf(
		"this share is held until %s, so that whoever this identity belongs to has a chance to stop it",
		e.Until.UTC().Format(time.RFC3339))
}

// ErrNeedsApproval says a person has to decide.
type ErrNeedsApproval struct{ IdentityAID string }

func (e *ErrNeedsApproval) Error() string {
	return "somebody needs to approve this recovery before this share is released"
}

// Holder is this machine's side of holding shares for other identities.
type Holder struct {
	DataDir string
	// Notify is called the first time a share is asked for, and is how a theft
	// becomes an event the owner hears about rather than one they never do. A
	// holder that cannot notify still records and still waits.
	Notify func(identityAID string, firstAsk bool)

	mu sync.Mutex
}

// Release decides whether to hand back the share in a request.
//
// The sealed share arrives in the request rather than being stored here, and
// that is not laziness: it means holding a share costs a private key and
// nothing else, and it means possession of the sealed share is itself evidence
// the requester opened the bootstrap envelope — which needs the recovery words.
// So a holder is asked only by somebody who already passed gate one.
func (h *Holder) Release(holding Holding, sealed backup.SealedShare, now time.Time) ([]byte, error) {
	if holding.HolderID != sealed.HolderID {
		return nil, fmt.Errorf("this share is addressed to a different holder")
	}

	// Whether this share is even ours is settled BEFORE anything else, and
	// before anything is written down.
	//
	// Opening it needs a private key only this holder has, so getting past
	// here is proof the caller holds a share genuinely addressed to us — which
	// in turn means they opened the bootstrap envelope, which needed the
	// recovery words. Everything after this point can therefore answer
	// honestly ("held until Tuesday") without telling a stranger anything,
	// because a stranger never reaches it.
	//
	// Doing it the other way round would make this route a probe: ask about an
	// identity, and the difference between "no such holding" and "held" tells
	// you whether this machine protects that identity at all.
	share, err := h.unseal(holding, sealed)
	if err != nil {
		return nil, err
	}

	h.mu.Lock()
	record, err := h.recordAsk(holding.IdentityAID, now)
	h.mu.Unlock()
	if err != nil {
		return nil, err
	}

	if record.Times == 1 && h.Notify != nil {
		h.Notify(holding.IdentityAID, true)
	}

	if holding.Policy.WaitHours > 0 {
		first, err := time.Parse(time.RFC3339, record.FirstAskedAt)
		if err != nil {
			return nil, fmt.Errorf("this holder's record of when it was first asked is unreadable: %w", err)
		}
		until := first.Add(time.Duration(holding.Policy.WaitHours) * time.Hour)
		if now.Before(until) {
			return nil, &ErrHeldForWait{Until: until, Remaining: until.Sub(now)}
		}
	}

	if holding.Policy.RequireApproval && !record.Approved {
		return nil, &ErrNeedsApproval{IdentityAID: holding.IdentityAID}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	record.ReleasedAt = now.UTC().Format(time.RFC3339)
	if err := h.save(record); err != nil {
		// The release is not reported as having happened unless it was
		// written down. A share handed out with no record is one nobody can
		// ever be told about.
		return nil, fmt.Errorf("could not record releasing this share: %w", err)
	}
	return share, nil
}

// Approve records that a person said yes.
// unseal opens a share addressed to this holder, and refuses everything else
// with one answer.
//
// One answer on purpose: a share sealed to somebody else, a malformed share
// and a share for an identity this machine has never heard of must not be
// distinguishable, or the difference is a way to enumerate what a machine
// holds and for whom.
func (h *Holder) unseal(holding Holding, sealed backup.SealedShare) ([]byte, error) {
	refuse := fmt.Errorf("this share was not sealed to this holder")

	priv, err := backup.DecodeB64(holding.PrivateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("this holder's key is unreadable: %w", err)
	}
	eph, err := backup.DecodeB64(sealed.EphemeralPubB64)
	if err != nil {
		return nil, refuse
	}
	wrapped, err := backup.DecodeB64(sealed.WrappedB64)
	if err != nil {
		return nil, refuse
	}
	nonce, err := backup.DecodeB64(sealed.NonceB64)
	if err != nil {
		return nil, refuse
	}
	share, err := backup.UnsealBEK(priv, eph, wrapped, nonce)
	if err != nil {
		return nil, refuse
	}
	return share, nil
}

func (h *Holder) Approve(identityAID string, now time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	record, err := h.load(identityAID)
	if err != nil {
		return err
	}
	if record == nil {
		// Approving a recovery nobody has asked about would let somebody
		// pre-approve their own future request.
		return fmt.Errorf("nothing has asked this holder for a share for that identity")
	}
	record.Approved = true
	record.ApprovedAt = now.UTC().Format(time.RFC3339)
	return h.save(record)
}

// WhatHasBeenAsked is every request this holder has seen, newest first, so a
// screen can put it in front of somebody.
func (h *Holder) WhatHasBeenAsked() ([]AskRecord, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	dir := h.asksDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []AskRecord
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var r AskRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("a record of being asked is unreadable: %w", err)
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastAskedAt > out[j].LastAskedAt })
	return out, nil
}

func (h *Holder) recordAsk(identityAID string, now time.Time) (*AskRecord, error) {
	record, err := h.load(identityAID)
	if err != nil {
		return nil, err
	}
	stamp := now.UTC().Format(time.RFC3339)
	if record == nil {
		record = &AskRecord{
			IdentityAID:  identityAID,
			FirstAskedAt: stamp,
		}
	}
	// FirstAskedAt is never touched again. It is the clock, and a clock that
	// can be restarted by asking again is a wait an attacker skips by asking
	// twice.
	record.Times++
	record.LastAskedAt = stamp
	if err := h.save(record); err != nil {
		return nil, err
	}
	return record, nil
}

func (h *Holder) asksDir() string { return filepath.Join(h.DataDir, "shares_asked_for") }

func (h *Holder) pathFor(identityAID string) string {
	return filepath.Join(h.asksDir(), backup.EncodeB64([]byte(identityAID))+".json")
}

func (h *Holder) load(identityAID string) (*AskRecord, error) {
	raw, err := os.ReadFile(h.pathFor(identityAID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var r AskRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("this holder's record for that identity is unreadable: %w", err)
	}
	return &r, nil
}

func (h *Holder) save(r *AskRecord) error {
	if err := os.MkdirAll(h.asksDir(), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	// Written aside and renamed, so a machine that loses power part-way
	// through does not come back with a half-written clock.
	path := h.pathFor(r.IdentityAID)
	tmp := path + ".writing"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
