package anchored

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"

	"identity-agent-core/atomicfile"
)

// FloorStore keeps the floors where whoever delivers lists cannot delete them.
// This slice has a file in the data directory (FileFloors). A platform's sealed
// store (Keychain, Keystore, DPAPI, the box's sealed volume) is another
// implementation, and not here.
type FloorStore interface {
	Load() (Floors, error)
	Save(Floors) error
}

// floorRecord is what a FileFloors holds.
type floorRecord struct {
	ListSequence   int64  `json:"list_sequence"`
	ListDigest     string `json:"list_digest"`
	HasKeyHistory  bool   `json:"has_key_history"`
	KeyHistorySN   int    `json:"key_history_sn"`
	KeyHistorySAID string `json:"key_history_said"`
	// NewestPublishedAt is absent in a file written before it existed, which
	// reads as none.
	NewestPublishedAt int64 `json:"newest_published_at,omitempty"`
}

// FileFloors keeps the floors in one file, written 0600.
type FileFloors struct{ Path string }

// Load returns the floors, none if the file does not exist. A file that exists
// and cannot be read is an error and never "nothing seen yet": reading damage
// as empty would reopen exactly what a floor closes.
func (f FileFloors) Load() (Floors, error) {
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return Floors{}, nil
	}
	if err != nil {
		return Floors{}, fmt.Errorf("reading the floors: %w", err)
	}
	damaged := fmt.Errorf("the floors file %s is damaged; refusing every list until it is restored or removed by hand", f.Path)
	var r floorRecord
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil || dec.More() || r.ListSequence < 0 || r.KeyHistorySN < 0 || r.NewestPublishedAt < 0 ||
		(r.HasKeyHistory && r.KeyHistorySAID == "") || (!r.HasKeyHistory && (r.KeyHistorySN != 0 || r.KeyHistorySAID != "")) {
		return Floors{}, damaged
	}
	return Floors{ListSequence: r.ListSequence, ListDigest: r.ListDigest, HasKeyHistory: r.HasKeyHistory,
		KeyHistorySN: r.KeyHistorySN, KeyHistorySAID: r.KeyHistorySAID, NewestPublishedAt: r.NewestPublishedAt}, nil
}

// Save writes the floors.
func (f FileFloors) Save(fl Floors) error {
	b, err := json.Marshal(floorRecord{fl.ListSequence, fl.ListDigest, fl.HasKeyHistory, fl.KeyHistorySN, fl.KeyHistorySAID, fl.NewestPublishedAt})
	if err != nil {
		return err
	}
	return atomicfile.Write(f.Path, append(b, '\n'), 0o600)
}

// Merge returns the higher of two sets of floors. Two that hold different
// content at the same place are a conflict, not a choice.
func Merge(a, b Floors) (Floors, error) {
	out := a
	if b.NewestPublishedAt > out.NewestPublishedAt {
		out.NewestPublishedAt = b.NewestPublishedAt
	}
	switch {
	case b.ListSequence > a.ListSequence:
		out.ListSequence, out.ListDigest = b.ListSequence, b.ListDigest
	case b.ListSequence == a.ListSequence && a.ListDigest != "" && b.ListDigest != "" && a.ListDigest != b.ListDigest:
		return Floors{}, fmt.Errorf("two different lists are held at sequence %d", a.ListSequence)
	case b.ListSequence == a.ListSequence && a.ListDigest == "":
		out.ListDigest = b.ListDigest
	}
	switch {
	case !b.HasKeyHistory:
	case !a.HasKeyHistory || b.KeyHistorySN > a.KeyHistorySN:
		out.HasKeyHistory, out.KeyHistorySN, out.KeyHistorySAID = true, b.KeyHistorySN, b.KeyHistorySAID
	case b.KeyHistorySN == a.KeyHistorySN && b.KeyHistorySAID != a.KeyHistorySAID:
		return Floors{}, fmt.Errorf("two different events are held at place %d of the publisher's history: %w", a.KeyHistorySN, ErrDuplicity)
	}
	return out, nil
}

// Checker is Verify with the floors kept: it reads them, never lets them be
// lower than its Snapshot, verifies, and records the new
// floors before the list is returned. A list is not used on the strength of a
// floor that did not stick.
type Checker struct {
	Pin      Pin
	Store    FloorStore
	Snapshot Floors // optional floors a caller starts from; the floors never fall below it (the server gives none)
	// Peers, if set, asks the person's peer watchers for the publisher's tip too.
	Peers PeerAsker
	mu    sync.Mutex
}

// Check verifies b against the witnesses' answers and the kept floors.
func (c *Checker) Check(b *Bundle, replies []TipReply, now time.Time) (*Result, error) {
	return c.CheckAsking(b, func(string, []string, int) ([]TipReply, error) { return replies, nil }, now)
}

// CheckAsking is Check that asks the witnesses itself, once the history is
// known to be genuine (VerifyAsking).
func (c *Checker) CheckAsking(b *Bundle, ask Asker, now time.Time) (*Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	held, err := c.Store.Load()
	if err != nil {
		return nil, err
	}
	floors, err := Merge(held, c.Snapshot)
	if err != nil {
		return nil, err
	}
	res, err := VerifyAskingAlso(b, c.Pin, ask, c.Peers, floors, now)
	if err != nil {
		return nil, err
	}
	next, err := Merge(floors, Floors{ListSequence: res.List.Sequence, ListDigest: res.CredentialSAID,
		HasKeyHistory: true, KeyHistorySN: res.Tip.SN, KeyHistorySAID: res.Tip.SAID,
		NewestPublishedAt: res.List.PublishedAt.Unix()})
	if err != nil {
		return nil, err
	}
	// Re-read and merge just before saving: another Checker over the same store
	// (the lock above covers only this one) may have saved higher floors while
	// this list was being checked. Merge never lowers anything, so what is
	// written is at least what is on disk and at least what was just accepted.
	latest, err := c.Store.Load()
	if err != nil {
		return nil, err
	}
	next, err = Merge(latest, next)
	if err != nil {
		return nil, err
	}
	if next != latest {
		if err := c.Store.Save(next); err != nil {
			return nil, fmt.Errorf("recording what was accepted: %w", err)
		}
	}
	return res, nil
}
