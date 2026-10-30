package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"identity-agent-core/activitylog"
	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
)

// invocationSigner signs invocation-log events (activitylog.EventSigner) with a stable
// pairwise identity: an HD-derived key (same derivation the ask-sign layer uses) whose
// AID is minted once via the KERI driver and persisted, so every audit event across
// restarts verifies against one published signer. The signing seed is re-derived from
// the root seed on demand — never stored.
type invocationSigner struct {
	s    *CoreServer
	mu   sync.Mutex
	aid  string
	key  ed25519.PrivateKey
	done bool
}

type invocationSignerRecord struct {
	AID   string `json:"aid"`
	Index int    `json:"index"`
	// ChainStart is where the log's signed chain begins. It lives here, outside
	// the database the log is in, so somebody who can rewrite that database
	// cannot move it (activitylog.ChainKeeper).
	ChainStart *activitylog.ChainStart `json:"chain_start,omitempty"`
}

// readInvocationSignerRecord reads the signer's record; found is false when
// there is none.
func readInvocationSignerRecord(dataDir string) (rec invocationSignerRecord, found bool, err error) {
	data, err := os.ReadFile(filepath.Join(dataDir, "invocation_signer.json"))
	if os.IsNotExist(err) {
		return rec, false, nil
	}
	if err != nil {
		return rec, false, err
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return rec, false, err
	}
	return rec, rec.AID != "", nil
}

// writeInvocationSignerRecord replaces the record in one step, so a crash
// never leaves half a record.
func writeInvocationSignerRecord(dataDir string, rec invocationSignerRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	path := filepath.Join(dataDir, "invocation_signer.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ChainStart implements activitylog.ChainKeeper.
func (sg *invocationSigner) ChainStart() (activitylog.ChainStart, bool, error) {
	rec, found, err := readInvocationSignerRecord(sg.s.DataDir)
	if err != nil || !found || rec.ChainStart == nil {
		return activitylog.ChainStart{}, false, err
	}
	return *rec.ChainStart, true, nil
}

// KeepChainStart implements activitylog.ChainKeeper. A start is kept once; after
// that the only change is filling in the hash of a start stamped when the
// signer was created, from the first row it signed, which can only be at or
// after the stamped id.
func (sg *invocationSigner) KeepChainStart(start activitylog.ChainStart) error {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	rec, found, err := readInvocationSignerRecord(sg.s.DataDir)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("invocation signer: no signer on record to keep the chain start with")
	}
	if rec.ChainStart != nil {
		if rec.ChainStart.Hash != "" || start.ID < rec.ChainStart.ID {
			return nil
		}
		rec.ChainStart.ID, rec.ChainStart.Hash = start.ID, start.Hash
		return writeInvocationSignerRecord(sg.s.DataDir, rec)
	}
	rec.ChainStart = &start
	return writeInvocationSignerRecord(sg.s.DataDir, rec)
}

// init derives (or restores) the signer identity lazily, on first sign — server
// dependencies (root seed, KERI driver) are ready by then.
func (sg *invocationSigner) init() error {
	if sg.done {
		return nil
	}
	rootSeed, err := secureenclave.LoadRootSeed(sg.s.DataDir)
	if err != nil {
		return fmt.Errorf("invocation signer: root seed unavailable: %w", err)
	}

	if rec, found, rerr := readInvocationSignerRecord(sg.s.DataDir); rerr == nil && found {
		seed, derr := backup.DerivePairwiseSeed(rootSeed, rec.Index, 0)
		if derr != nil {
			return fmt.Errorf("invocation signer: derive seed: %w", derr)
		}
		sg.aid = rec.AID
		sg.key = ed25519.NewKeyFromSeed(seed)
		sg.done = true
		return nil
	}

	if sg.s.KeriDriver == nil {
		return fmt.Errorf("invocation signer: keri driver required to mint the signer AID")
	}
	idx, aerr := sg.s.DataStore.AllocateNextRelationshipIndex("invocation-log")
	if aerr != nil {
		return fmt.Errorf("invocation signer: allocate index: %w", aerr)
	}
	seed, derr := backup.DerivePairwiseSeed(rootSeed, idx, 0)
	if derr != nil {
		return fmt.Errorf("invocation signer: derive seed: %w", derr)
	}
	nextSeed, _ := backup.DerivePairwiseSeed(rootSeed, idx, 1)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	nextPub := ed25519.NewKeyFromSeed(nextSeed).Public().(ed25519.PublicKey)
	icp, ierr := sg.s.KeriDriver.CreateInceptionNamed(
		iacrypto.VerkeyQB64(pub),
		iacrypto.VerkeyQB64(nextPub),
		fmt.Sprintf("invocation-log-%d", idx),
	)
	if ierr != nil || icp.AID == "" {
		return fmt.Errorf("invocation signer: mint inception: %w", ierr)
	}
	// The chain begins with this signer: stamp where, before it signs anything,
	// so no row it writes is ever outside the chain, even if the process stops
	// between writing the first row and recording it.
	rec := invocationSignerRecord{AID: icp.AID, Index: idx}
	if sg.s.ActivityLog != nil {
		next, nerr := sg.s.ActivityLog.NextEventID()
		if nerr != nil {
			return fmt.Errorf("invocation signer: find where its chain begins: %w", nerr)
		}
		rec.ChainStart = &activitylog.ChainStart{ID: next, Linked: true, PayloadFrom: next}
	}
	if werr := writeInvocationSignerRecord(sg.s.DataDir, rec); werr != nil {
		return fmt.Errorf("invocation signer: persist record: %w", werr)
	}
	sg.aid = icp.AID
	sg.key = ed25519.NewKeyFromSeed(seed)
	sg.done = true
	return nil
}

// SignEvent implements activitylog.EventSigner.
func (sg *invocationSigner) SignEvent(payload []byte) (string, string, error) {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	if err := sg.init(); err != nil {
		return "", "", err
	}
	sig := ed25519.Sign(sg.key, payload)
	return sg.aid, base64.RawURLEncoding.EncodeToString(sig), nil
}

// invocationSignerKey returns the public key of this agent's log signer when aid
// is that signer, for checking the log's signatures. It only reads: checking a
// log must never be what mints a signer, or a log with no signer would come back
// signed by one created to check it.
//
// When the key cannot be had right now (no signer record to read, no root
// seed), the error wraps activitylog.ErrCannotCheck: that is a reason the log
// cannot be checked, never evidence that it was changed.
func (s *CoreServer) invocationSignerKey(aid string) (ed25519.PublicKey, error) {
	rec, found, err := readInvocationSignerRecord(s.DataDir)
	if err != nil {
		return nil, fmt.Errorf("%w: the log signer's record cannot be read: %v", activitylog.ErrCannotCheck, err)
	}
	if !found {
		return nil, fmt.Errorf("%w: this agent has no log signer on record", activitylog.ErrCannotCheck)
	}
	if rec.AID != aid {
		return nil, fmt.Errorf("not this agent's log signer (%s)", rec.AID)
	}
	rootSeed, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		return nil, fmt.Errorf("%w: root seed unavailable: %v", activitylog.ErrCannotCheck, err)
	}
	seed, err := backup.DerivePairwiseSeed(rootSeed, rec.Index, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", activitylog.ErrCannotCheck, err)
	}
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil
}
