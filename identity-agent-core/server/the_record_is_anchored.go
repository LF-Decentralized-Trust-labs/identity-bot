package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
	"identity-agent-core/store"
)

// The record is anchored in a key log.
//
// The governance log and every conversation are chains: each row names the
// hash of the one before it, and each row is signed. That catches a row
// edited, removed or reordered in the middle. It cannot catch the newest rows
// being removed, because nothing after them names them; nor a whole chain
// rewritten and re-signed by whoever holds the signer's key.
//
// So the heads are anchored. A record identity, delegated from this identity
// and approved in its key log, writes an interaction whose seal is the digest
// of a statement naming the log's newest row and its hash, and the newest
// entry of every conversation that changed since the last anchoring. Anything
// before an anchor is then fixed: a verifier finds the statement's digest in
// the record identity's key log and checks the rows it names are still there
// and unchanged. What was written after the newest anchor is not yet fixed,
// and is reported as such, never as checked.
//
// A dedicated identity rather than this identity's own log, because anchoring
// is frequent and this identity's log governs everything: it should carry its
// approvals, not a stream of digests.
//
// Anchoring runs at most every anchorInterval, sooner once anchorEvery
// messages have been recorded, and only when something changed.

const recordIdentityFile = "record_identity.json"

var (
	anchorInterval = durationFromEnv("RECORD_ANCHOR_INTERVAL", 5*time.Minute)
	anchorEvery    = intFromEnv("RECORD_ANCHOR_EVERY", 20)
)

func durationFromEnv(name string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(os.Getenv(name)); err == nil && d > 0 {
		return d
	}
	return def
}

func intFromEnv(name string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(name)); err == nil && n > 0 {
		return n
	}
	return def
}

// recordIdentityRecord is where the record identity's keys come from.
type recordIdentityRecord struct {
	AID   string `json:"aid"`
	Index int    `json:"index"`
}

// anchorStatement is what one anchoring fixes. Its digest is the seal.
type anchorStatement struct {
	Log           anchoredLog            `json:"log"`
	Conversations []anchoredConversation `json:"conversations,omitempty"`
	At            string                 `json:"at"`
}

type anchoredLog struct {
	Row  int64  `json:"row"`
	Head string `json:"head"`
}

type anchoredConversation struct {
	ID   string `json:"id"`
	Seq  int    `json:"seq"`
	Head string `json:"head"`
}

// recordMu serialises creating the record identity and anchoring: two
// anchorings at once would build on the same tip of its log.
var recordMu sync.Mutex

// recorded counts messages since the last anchoring.
var recorded atomic.Int64

func (s *CoreServer) recordIdentityPath() string {
	return filepath.Join(s.DataDir, recordIdentityFile)
}

// recordKeys derives the record identity's signing seed and the two public
// keys its inception commits to.
func (s *CoreServer) recordKeys(index int) ([]byte, string, string, error) {
	rootSeed, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		return nil, "", "", fmt.Errorf("no root seed to derive the record identity from: %w", err)
	}
	seed, err := backup.DerivePairwiseSeed(rootSeed, index, 0)
	if err != nil {
		return nil, "", "", err
	}
	next, err := backup.DerivePairwiseSeed(rootSeed, index, 1)
	if err != nil {
		return nil, "", "", err
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	nextPub := ed25519.NewKeyFromSeed(next).Public().(ed25519.PublicKey)
	return seed, iacrypto.VerkeyQB64(pub), iacrypto.VerkeyQB64(nextPub), nil
}

func (s *CoreServer) loadRecordIdentity() (recordIdentityRecord, bool) {
	var rec recordIdentityRecord
	b, err := os.ReadFile(s.recordIdentityPath())
	if err != nil || json.Unmarshal(b, &rec) != nil || rec.AID == "" {
		return rec, false
	}
	return rec, true
}

// recordIdentity is the record identity and its signing seed, made the first
// time it is needed. Callers hold recordMu.
func (s *CoreServer) recordIdentity() (string, []byte, error) {
	if rec, ok := s.loadRecordIdentity(); ok {
		seed, _, _, err := s.recordKeys(rec.Index)
		return rec.AID, seed, err
	}
	keeper, ok := s.KeriDriver.(drivers.KELKeeper)
	if !ok || s.DataStore == nil {
		return "", nil, fmt.Errorf("this Identity Agent cannot keep a key log, so it cannot anchor its record")
	}
	owner, err := s.DataStore.GetIdentity()
	if err != nil || owner == nil {
		return "", nil, fmt.Errorf("this Identity Agent has no identity to anchor its record under")
	}
	// The approval is an event in this identity's own key log. Where its key
	// lives on another device, that device has to sign it, and this Identity
	// Agent writes nothing there it could not sign.
	if _, err := s.identitySigningSeed(); err != nil {
		return "", nil, fmt.Errorf("the identity's key is not held here, so the record identity cannot be approved here: %w", err)
	}
	index, err := s.DataStore.AllocateNextRelationshipIndex("record")
	if err != nil {
		return "", nil, err
	}
	seed, pub, nextPub, err := s.recordKeys(index)
	if err != nil {
		return "", nil, err
	}
	var aid string
	keep := func(k drivers.KELKeep) error {
		approval, dip, err := s.delegationRecords(owner.AID, k, pub, seed)
		if err != nil {
			return err
		}
		aid = dip.AID
		// Where the keys come from is written first, so an identity kept in
		// the log is never one this Identity Agent cannot sign as.
		b, _ := json.Marshal(recordIdentityRecord{AID: aid, Index: index})
		if err := os.WriteFile(s.recordIdentityPath(), b, 0o600); err != nil {
			return err
		}
		if err := s.DataStore.KeepEvents(approval, dip); err != nil {
			os.Remove(s.recordIdentityPath())
			return err
		}
		return nil
	}
	if _, err := keeper.CreateDelegatedInceptionKept(pub, nextPub, "", owner.AID, keep); err != nil {
		return "", nil, fmt.Errorf("the record identity could not be made: %w", err)
	}
	log.Printf("[record] record identity %s made, approved in %s's key log", aid, owner.AID)
	return aid, seed, nil
}

// delegationRecords are the stored forms of a delegation: the delegator's
// approval, signed by this identity, and the delegated inception, signed by its
// own key.
func (s *CoreServer) delegationRecords(delegator string, k drivers.KELKeep, pub string, seed []byte) (store.EventRecord, store.EventRecord, error) {
	var ixn, dip map[string]interface{}
	if err := json.Unmarshal(k.Raw, &ixn); err != nil {
		return store.EventRecord{}, store.EventRecord{}, err
	}
	if err := json.Unmarshal(k.Delegated, &dip); err != nil {
		return store.EventRecord{}, store.EventRecord{}, err
	}
	approval, err := s.ownInteractionRecord(delegator, ixn, base64.StdEncoding.EncodeToString(k.Raw), k.SN, "")
	if err != nil {
		return store.EventRecord{}, store.EventRecord{}, err
	}
	sig, err := signEventBytes(k.Delegated, seed)
	if err != nil {
		return store.EventRecord{}, store.EventRecord{}, err
	}
	aid, _ := dip["i"].(string)
	return approval, store.EventRecord{
		AID: aid, SequenceNumber: 0, EventType: "dip", EventJSON: string(k.Delegated),
		Timestamp: time.Now().UTC().Format(time.RFC3339), RawBytesB64: base64.StdEncoding.EncodeToString(k.Delegated),
		PublicKey: pub, CesrSignature: sig,
	}, nil
}

// reloadRecordIdentity hands the record identity's stored key log back to the
// engine after a restart, so the next anchoring chains to the last one kept.
func (s *CoreServer) reloadRecordIdentity() {
	rec, ok := s.loadRecordIdentity()
	if !ok || s.KeriDriver == nil || s.DataStore == nil {
		return
	}
	events, err := s.DataStore.GetEvents(rec.AID)
	if err != nil || len(events) == 0 {
		log.Printf("[record] the record identity %s has no stored key log to reload: %v", rec.AID, err)
		return
	}
	kel, raws, lastSAID, lastSN := kelFromEvents(events)
	_, pub, _, err := s.recordKeys(rec.Index)
	if err != nil {
		log.Printf("[record] the record identity's keys: %v", err)
		return
	}
	if _, err := s.KeriDriver.ReloadIdentity(&drivers.DriverReloadIdentityRequest{
		AID: rec.AID, PublicKey: pub, SequenceNumber: lastSN, LastSAID: lastSAID, KEL: kel, RawEventsB64: raws,
	}); err != nil {
		log.Printf("[record] the record identity %s could not be reloaded: %v", rec.AID, err)
	}
}

// anchorRecord anchors the log's head and the heads of the conversations that
// changed since the last anchoring. It reports whether it anchored anything.
func (s *CoreServer) anchorRecord() (bool, error) {
	if s.SandboxManager == nil || s.SandboxManager.Store() == nil || s.DataStore == nil {
		return false, nil
	}
	recordMu.Lock()
	defer recordMu.Unlock()
	recorded.Store(0)

	anchors, err := s.DataStore.GetRecordAnchors()
	if err != nil {
		return false, err
	}
	var last anchorStatement
	var since time.Time
	if len(anchors) > 0 {
		if err := json.Unmarshal([]byte(anchors[len(anchors)-1].Statement), &last); err != nil {
			return false, fmt.Errorf("the last anchoring is unreadable: %w", err)
		}
		since, _ = time.Parse(time.RFC3339Nano, last.At)
	}
	row, head, err := s.SandboxManager.Store().Head()
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()
	st := anchorStatement{Log: anchoredLog{Row: row, Head: head}, At: now.Format(time.RFC3339Nano)}
	if convs, err := s.conversations(); err == nil {
		changed, err := convs.ChangedSince(since)
		if err != nil {
			return false, err
		}
		for _, c := range changed {
			st.Conversations = append(st.Conversations, anchoredConversation{ID: c.ID, Seq: c.Seq, Head: c.HeadHash})
		}
	}
	if row == 0 || (row == last.Log.Row && head == last.Log.Head && len(st.Conversations) == 0) {
		return false, nil
	}

	aid, seed, err := s.recordIdentity()
	if err != nil {
		return false, err
	}
	statement, err := json.Marshal(st)
	if err != nil {
		return false, err
	}
	digest, err := iacrypto.Blake3QB64(statement)
	if err != nil {
		return false, err
	}
	pub := iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	keep := func(k drivers.KELKeep) error {
		sig, err := signEventBytes(k.Raw, seed)
		if err != nil {
			return err
		}
		var ixn map[string]interface{}
		if err := json.Unmarshal(k.Raw, &ixn); err != nil {
			return err
		}
		said, _ := ixn["d"].(string)
		return s.DataStore.KeepRecordAnchor(store.EventRecord{
			AID: aid, SequenceNumber: k.SN, EventType: "ixn", EventJSON: string(k.Raw),
			Timestamp: now.Format(time.RFC3339), RawBytesB64: base64.StdEncoding.EncodeToString(k.Raw),
			PublicKey: pub, CesrSignature: sig,
		}, store.RecordAnchor{Seq: k.SN, SAID: said, Statement: string(statement), Digest: digest, CreatedAt: st.At})
	}
	keeper, ok := s.KeriDriver.(drivers.KELKeeper)
	if !ok {
		return false, fmt.Errorf("this Identity Agent cannot keep a key log, so it cannot anchor its record")
	}
	if _, err := keeper.InteractKept(aid, []interface{}{map[string]interface{}{"d": digest}}, keep); err != nil {
		return false, fmt.Errorf("the record could not be anchored: %w", err)
	}
	return true, nil
}

// noteRecorded counts one recorded message, anchoring once enough have been.
func (s *CoreServer) noteRecorded() {
	if recorded.Add(1) >= int64(anchorEvery) {
		recorded.Store(0)
		go func() {
			if _, err := s.anchorRecord(); err != nil {
				log.Printf("[record] anchoring: %v", err)
			}
		}()
	}
}

// keepAnchoring anchors the record every anchorInterval until stop closes.
func (s *CoreServer) keepAnchoring(stop <-chan struct{}) {
	t := time.NewTicker(anchorInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if _, err := s.anchorRecord(); err != nil {
				log.Printf("[record] anchoring: %v", err)
			}
		}
	}
}

// anchorCheck is what the anchors show about the record.
type anchorCheck struct {
	// AnchoredThrough is the newest log row an anchor fixes; Unanchored the
	// rows written since, which no anchor yet covers.
	AnchoredThrough int64
	Unanchored      int64
	// BrokenAt is the place in the record identity's key log of the first
	// anchor that no longer holds, and Why says what failed. Zero when every
	// anchor holds.
	BrokenAt int
	Why      string
}

// checkAnchors checks every anchoring: the statement digests to the seal, the
// record identity's key log carries that seal at that place, signed, and every
// row and conversation entry the statement names is still there, unchanged.
func (s *CoreServer) checkAnchors() (anchorCheck, error) {
	var out anchorCheck
	if s.DataStore == nil || s.SandboxManager == nil || s.SandboxManager.Store() == nil {
		return out, nil
	}
	anchors, err := s.DataStore.GetRecordAnchors()
	if err != nil || len(anchors) == 0 {
		return out, err
	}
	rec, ok := s.loadRecordIdentity()
	if !ok {
		return anchorCheck{BrokenAt: anchors[0].Seq, Why: "there are anchors but no record identity to have made them"}, nil
	}
	events, err := s.DataStore.GetEvents(rec.AID)
	if err != nil {
		return out, err
	}
	kel := map[int]store.EventRecord{}
	in := drivers.ValidateKELInput{AID: rec.AID}
	for _, ev := range events {
		kel[ev.SequenceNumber] = ev
		raw, _ := base64.StdEncoding.DecodeString(ev.RawBytesB64)
		in.RawEvents = append(in.RawEvents, raw)
		in.CesrSignatures = append(in.CesrSignatures, ev.CesrSignature)
	}
	if got, err := drivers.ValidateKELFromBytes(in); err != nil || !got.KelVerified {
		return anchorCheck{BrokenAt: anchors[0].Seq, Why: "the record identity's key log does not verify"}, nil
	}
	convs, _ := s.conversations()
	rows := s.SandboxManager.Store()
	for _, a := range anchors {
		broken := func(why string) (anchorCheck, error) {
			return anchorCheck{BrokenAt: a.Seq, Why: why}, nil
		}
		if d, _ := iacrypto.Blake3QB64([]byte(a.Statement)); d != a.Digest {
			return broken("what was anchored no longer digests to its seal")
		}
		ev, ok := kel[a.Seq]
		if !ok || !carriesSeal(ev.RawBytesB64, a.Digest) {
			return broken("the record identity's key log does not carry this anchor")
		}
		var st anchorStatement
		if err := json.Unmarshal([]byte(a.Statement), &st); err != nil {
			return broken("what was anchored is unreadable")
		}
		if h, there, err := rows.RowHash(st.Log.Row); err != nil {
			return out, err
		} else if !there || h != st.Log.Head {
			return broken(fmt.Sprintf("log row %d, which this anchor fixes, has been removed or changed", st.Log.Row))
		}
		for _, c := range st.Conversations {
			if convs == nil {
				return broken("the conversations this anchor fixes cannot be read")
			}
			e, err := convs.EntryAt(c.ID, c.Seq)
			if err != nil || e.Hash != c.Head {
				return broken(fmt.Sprintf("entry %d of conversation %s, which this anchor fixes, has been removed or changed", c.Seq, c.ID))
			}
		}
		out.AnchoredThrough = st.Log.Row
	}
	n, err := rows.RowsAfter(out.AnchoredThrough)
	if err != nil {
		return out, err
	}
	out.Unanchored = n
	return out, nil
}

// carriesSeal reports whether a stored interaction's seals include digest.
func carriesSeal(rawB64, digest string) bool {
	raw, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return false
	}
	var ev struct {
		A []map[string]interface{} `json:"a"`
	}
	if json.Unmarshal(raw, &ev) != nil {
		return false
	}
	for _, seal := range ev.A {
		if seal["d"] == digest {
			return true
		}
	}
	return false
}
