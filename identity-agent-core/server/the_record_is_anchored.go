package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/conversation"
	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
	"identity-agent-core/store"
)

// The record is anchored in a key log.
//
// The governance log and every conversation are chains: each row names the
// hash of the one before it, and each row is signed. That catches a row
// edited, removed or reordered in the middle. It cannot catch the newest rows
// being removed, because nothing after them names them.
//
// So the heads are anchored. A record identity, delegated from this identity
// and approved in its key log, writes interactions whose seal is the digest of
// a statement naming the log's newest row and its hash, and the newest entry
// of every conversation that grew since it was last anchored. The record
// identity's key log is the authority: every interaction in it must have its
// statement, every statement must be sealed in it, and every row and entry a
// statement names must still be there unchanged.
//
// WHAT THIS PROVES, AND TO WHOM. The record identity names the same witnesses
// as this identity, and each anchoring is sent to them for receipts. Once an
// anchoring is receipted, removing it, or anything it fixes, contradicts what
// the witnesses hold: anybody who asks them can tell, whoever controls this
// Identity Agent's database. Where this identity names no witnesses there is
// nobody outside to contradict it, and the report says so: the anchors then
// stop someone who can edit the record's rows but holds neither the record
// identity's key nor the place its key log's tip is kept outside the
// database. They do not stop someone who controls this Identity Agent
// entirely, who can rewrite the record and anchor it again.
//
// What was written after the newest anchoring is not fixed by anything yet,
// and is reported as unanchored, never as checked.
//
// Anchoring runs where it is wanted: for an organisation, and for any Identity
// Agent that holds AI agents. It runs at most every anchorInterval, sooner once
// anchorEvery messages have been recorded, and always within half the time a
// quiet conversation takes to close, so a conversation's last entry is anchored
// before it closes.

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

// recordState is the record's anchoring, held by the server.
type recordState struct {
	// mu serialises making the record identity and anchoring: two anchorings
	// at once would build on the same tip of its log.
	mu sync.Mutex
	// recorded counts messages since the last anchoring.
	recorded atomic.Int64
	// anchoredSeq is each conversation's newest anchored entry, read from the
	// anchors once and kept up to date. Sequences, not times: a clock that
	// steps, or an entry stamped before it is committed, cannot hide one.
	anchoredSeq map[string]int
}

// recordIdentityRecord is where the record identity's keys come from, and the
// tip of its key log as last anchored. Kept outside the database, so emptying
// the database's newest anchors leaves a tip they no longer reach.
type recordIdentityRecord struct {
	AID   string `json:"aid"`
	Index int    `json:"index"`
	// Pending is set while the identity is being made, and cleared once its
	// inception is kept. One found pending at start is finished or removed.
	Pending bool   `json:"pending,omitempty"`
	TipSN   int    `json:"tip_sn"`
	TipSAID string `json:"tip_said"`
	// TipSig is the record identity's signature over the tip, so the tip
	// cannot be lowered by somebody who can write this file but does not hold
	// the record identity's key. It sits beside the database and is exposed to
	// whoever can write the data directory; against them, only the witnesses
	// protect the record.
	TipSig string `json:"tip_sig,omitempty"`
}

func tipMessage(rec recordIdentityRecord) string {
	return fmt.Sprintf("record-tip\n%s\n%d\n%s", rec.AID, rec.TipSN, rec.TipSAID)
}

// signTip signs the record identity's tip with its own key.
func signTip(rec *recordIdentityRecord, seed []byte) error {
	sig, err := login.SignString(tipMessage(*rec), seed)
	if err != nil {
		return err
	}
	rec.TipSig = sig
	return nil
}

// recordScan is how many places in the record pool are searched for record
// identities this identity approved.
const recordScan = 32

// errRecordGone is a record identity this identity approved whose record here
// is gone. A second one is never made in its place.
var errRecordGone = errors.New("this identity approved a record identity whose record here is gone; a second one is not made")

// approvedRecordIdentities are the record identities this identity's key log
// approves. Each is recognised from its keys, derived from the record pool,
// under each set of witnesses this identity has named: so they are found from
// the key log itself, whatever has happened to the files that name them.
func (s *CoreServer) approvedRecordIdentities(owner string) ([]string, error) {
	events, err := s.DataStore.GetEvents(owner)
	if err != nil {
		return nil, err
	}
	sealed := map[string]string{}
	type config struct {
		witnesses []string
		toad      int
	}
	configs := []config{{nil, 0}}
	var current []string
	for _, ev := range events {
		raw, _ := base64.StdEncoding.DecodeString(ev.RawBytesB64)
		var parsed map[string]interface{}
		if json.Unmarshal(raw, &parsed) != nil {
			continue
		}
		switch parsed["t"] {
		case "icp":
			current = stringsOf(parsed["b"])
			configs = append(configs, config{current, thresholdOf(parsed["bt"])})
		case "rot":
			cut := map[string]bool{}
			for _, w := range stringsOf(parsed["br"]) {
				cut[w] = true
			}
			var next []string
			for _, w := range current {
				if !cut[w] {
					next = append(next, w)
				}
			}
			current = append(next, stringsOf(parsed["ba"])...)
			configs = append(configs, config{current, thresholdOf(parsed["bt"])})
		}
		seals, _ := parsed["a"].([]interface{})
		for _, x := range seals {
			if seal, ok := x.(map[string]interface{}); ok && seal["s"] == "0" {
				i, _ := seal["i"].(string)
				d, _ := seal["d"].(string)
				sealed[i] = d
			}
		}
	}
	base, err := store.PoolBase("record")
	if err != nil {
		return nil, err
	}
	var found []string
	for index := base; index < base+recordScan; index++ {
		_, pub, nextPub, err := s.recordKeys(index)
		if err != nil {
			return nil, err
		}
		for _, c := range configs {
			aid, said, err := keriengine.DelegatedInceptionOf(pub, nextPub, owner, c.witnesses, c.toad)
			if err == nil && sealed[aid] == said {
				found = append(found, aid)
				break
			}
		}
	}
	return found, nil
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

func (s *CoreServer) recordIdentityPath() string {
	return filepath.Join(s.DataDir, recordIdentityFile)
}

func (s *CoreServer) loadRecordIdentity() (recordIdentityRecord, bool) {
	var rec recordIdentityRecord
	b, err := os.ReadFile(s.recordIdentityPath())
	if err != nil || json.Unmarshal(b, &rec) != nil || rec.AID == "" {
		return rec, false
	}
	return rec, true
}

func (s *CoreServer) saveRecordIdentity(rec recordIdentityRecord) error {
	b, _ := json.Marshal(rec)
	tmp := s.recordIdentityPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.recordIdentityPath())
}

// anchorsItsRecord reports whether this Identity Agent anchors its record: an
// organisation does, and so does any Identity Agent that holds AI agents. An
// individual's phone with no AI agent writes nothing into its key log unasked.
func (s *CoreServer) anchorsItsRecord() bool {
	if strings.EqualFold(s.ourEntityType(), "organization") || strings.EqualFold(s.ourEntityType(), "organisation") {
		return true
	}
	if s.assetHandler != nil {
		for _, a := range s.assetHandler.Store.ListAssets() {
			if a.AssetType == "ai_agent" {
				return true
			}
		}
	}
	return false
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

// repairRecordIdentity finishes or removes a record identity left pending by
// a stop part way through making it: kept if its inception reached the
// database, removed if it did not.
func (s *CoreServer) repairRecordIdentity() {
	rec, ok := s.loadRecordIdentity()
	if !ok || !rec.Pending || s.DataStore == nil {
		return
	}
	events, _ := s.DataStore.GetEvents(rec.AID)
	if len(events) > 0 {
		rec.Pending = false
		if err := s.saveRecordIdentity(rec); err != nil {
			log.Printf("[record] the record identity %s could not be marked made: %v", rec.AID, err)
		}
		return
	}
	if err := os.Remove(s.recordIdentityPath()); err != nil {
		log.Printf("[record] a record identity that was never kept could not be removed: %v", err)
	}
}

// recordIdentity is the record identity and its signing seed, made the first
// time it is needed. Callers hold s.record.mu.
func (s *CoreServer) recordIdentity() (recordIdentityRecord, []byte, error) {
	s.repairRecordIdentity()
	if rec, ok := s.loadRecordIdentity(); ok {
		seed, _, _, err := s.recordKeys(rec.Index)
		return rec, seed, err
	}
	keeper, ok := s.KeriDriver.(drivers.KELKeeper)
	if !ok || s.DataStore == nil {
		return recordIdentityRecord{}, nil, fmt.Errorf("this Identity Agent cannot keep a key log, so it cannot anchor its record")
	}
	owner, err := s.DataStore.GetIdentity()
	if err != nil || owner == nil {
		return recordIdentityRecord{}, nil, fmt.Errorf("this Identity Agent has no identity to anchor its record under")
	}
	// The approval is an event in this identity's own key log. Where its key
	// lives on another device, that device has to sign it, and this Identity
	// Agent writes nothing there it could not sign.
	if _, err := s.identitySigningSeed(); err != nil {
		return recordIdentityRecord{}, nil, errKeyElsewhere
	}
	if found, err := s.approvedRecordIdentities(owner.AID); err != nil {
		return recordIdentityRecord{}, nil, err
	} else if len(found) > 0 {
		return recordIdentityRecord{}, nil, errRecordGone
	}
	if latest, err := s.DataStore.GetLatestRecordAnchor(); err != nil || latest != nil {
		return recordIdentityRecord{}, nil, errRecordGone
	}
	witnesses, toad, err := keeper.WitnessConfig(owner.AID)
	if err != nil {
		return recordIdentityRecord{}, nil, fmt.Errorf("this identity's witnesses: %w", err)
	}
	index, err := s.DataStore.AllocateNextRelationshipIndex("record")
	if err != nil {
		return recordIdentityRecord{}, nil, err
	}
	seed, pub, nextPub, err := s.recordKeys(index)
	if err != nil {
		return recordIdentityRecord{}, nil, err
	}
	var rec recordIdentityRecord
	var dipRecord, approvalRecord store.EventRecord
	keep := func(k drivers.KELKeep) error {
		approval, dip, err := s.delegationRecords(owner.AID, k, pub, seed)
		if err != nil {
			return err
		}
		dipRecord, approvalRecord = dip, approval
		var parsed map[string]interface{}
		_ = json.Unmarshal(k.Delegated, &parsed)
		said, _ := parsed["d"].(string)
		rec = recordIdentityRecord{AID: dip.AID, Index: index, Pending: true, TipSN: 0, TipSAID: said}
		if err := signTip(&rec, seed); err != nil {
			return err
		}
		// Marked pending before the inception is kept, and cleared after, so a
		// stop in between is finished or undone at the next start.
		if err := s.saveRecordIdentity(rec); err != nil {
			return err
		}
		if err := s.DataStore.KeepEvents(approval, dip); err != nil {
			os.Remove(s.recordIdentityPath())
			return err
		}
		return nil
	}
	if _, err := keeper.CreateDelegatedInceptionKept(pub, nextPub, "", owner.AID, witnesses, toad, keep); err != nil {
		return recordIdentityRecord{}, nil, fmt.Errorf("the record identity could not be made: %w", err)
	}
	rec.Pending = false
	if err := s.saveRecordIdentity(rec); err != nil {
		log.Printf("[record] the record identity %s was made but could not be marked so: %v", rec.AID, err)
	}
	// The approval goes to this identity's witnesses, and the inception to the
	// same ones, so a witness that checks a delegation against its approval
	// finds it.
	s.witness(owner.AID, approvalRecord, witnesses, toad)
	s.witness(rec.AID, dipRecord, witnesses, toad)
	log.Printf("[record] record identity %s made, approved in %s's key log, witnessed by %d", rec.AID, owner.AID, len(witnesses))
	return rec, seed, nil
}

// witness sends one of the record identity's events to the witnesses it
// names, for receipts. Nothing to do where it names none.
func (s *CoreServer) witness(aid string, ev store.EventRecord, witnesses []string, toad int) {
	if len(witnesses) == 0 || s.WitnessService == nil {
		return
	}
	raw, _ := base64.StdEncoding.DecodeString(ev.RawBytesB64)
	if err := s.WitnessService.BroadcastToDesignated(context.Background(), aid, raw, ev.CesrSignature, witnesses, toad); err != nil {
		log.Printf("[record] event %d of %s could not be sent to its witnesses: %v", ev.SequenceNumber, aid, err)
	}
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
	s.repairRecordIdentity()
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

// anchoredSeqs is each conversation's newest anchored entry. Callers hold
// s.record.mu.
func (s *CoreServer) anchoredSeqs() (map[string]int, error) {
	if s.record.anchoredSeq != nil {
		return s.record.anchoredSeq, nil
	}
	anchors, err := s.DataStore.GetRecordAnchors()
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, a := range anchors {
		var st anchorStatement
		if json.Unmarshal([]byte(a.Statement), &st) != nil {
			continue
		}
		for _, c := range st.Conversations {
			if c.Seq > out[c.ID] {
				out[c.ID] = c.Seq
			}
		}
	}
	s.record.anchoredSeq = out
	return out, nil
}

// anchorRecord anchors the log's head and the newest entry of every
// conversation that grew since it was last anchored. It reports whether it
// anchored anything.
func (s *CoreServer) anchorRecord() (bool, error) {
	if s.SandboxManager == nil || s.SandboxManager.Store() == nil || s.DataStore == nil || !s.anchorsItsRecord() {
		return false, nil
	}
	s.record.mu.Lock()
	defer s.record.mu.Unlock()
	s.record.recorded.Store(0)

	anchored, err := s.anchoredSeqs()
	if err != nil {
		return false, err
	}
	var last anchorStatement
	if latest, err := s.DataStore.GetLatestRecordAnchor(); err != nil {
		return false, err
	} else if latest != nil {
		if err := json.Unmarshal([]byte(latest.Statement), &last); err != nil {
			return false, fmt.Errorf("the last anchoring is unreadable: %w", err)
		}
	}
	row, head, err := s.SandboxManager.Store().Head()
	if err != nil {
		return false, err
	}
	st := anchorStatement{Log: anchoredLog{Row: row, Head: head}, At: time.Now().UTC().Format(time.RFC3339Nano)}
	if convs, err := s.conversations(); err == nil {
		heads, err := convs.Heads()
		if err != nil {
			return false, err
		}
		for _, c := range heads {
			if c.Seq > anchored[c.ID] {
				st.Conversations = append(st.Conversations, anchoredConversation{ID: c.ID, Seq: c.Seq, Head: c.HeadHash})
			}
		}
	}
	if len(st.Conversations) == 0 && (row == 0 || (row == last.Log.Row && head == last.Log.Head)) {
		return false, nil
	}
	sortConversations(st.Conversations)

	rec, seed, err := s.recordIdentity()
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
	var kept store.EventRecord
	var said string
	keep := func(k drivers.KELKeep) error {
		sig, err := signEventBytes(k.Raw, seed)
		if err != nil {
			return err
		}
		var ixn map[string]interface{}
		if err := json.Unmarshal(k.Raw, &ixn); err != nil {
			return err
		}
		said, _ = ixn["d"].(string)
		kept = store.EventRecord{
			AID: rec.AID, SequenceNumber: k.SN, EventType: "ixn", EventJSON: string(k.Raw),
			Timestamp: time.Now().UTC().Format(time.RFC3339), RawBytesB64: base64.StdEncoding.EncodeToString(k.Raw),
			PublicKey: pub, CesrSignature: sig,
		}
		return s.DataStore.KeepRecordAnchor(kept, store.RecordAnchor{Seq: k.SN, SAID: said, Statement: string(statement), Digest: digest, CreatedAt: st.At})
	}
	keeper, ok := s.KeriDriver.(drivers.KELKeeper)
	if !ok {
		return false, fmt.Errorf("this Identity Agent cannot keep a key log, so it cannot anchor its record")
	}
	if _, err := keeper.InteractKept(rec.AID, []interface{}{map[string]interface{}{"d": digest}}, keep); err != nil {
		return false, fmt.Errorf("the record could not be anchored: %w", err)
	}
	for _, c := range st.Conversations {
		anchored[c.ID] = c.Seq
	}
	rec.TipSN, rec.TipSAID = kept.SequenceNumber, said
	if err := signTip(&rec, seed); err != nil {
		log.Printf("[record] the record identity's tip could not be signed: %v", err)
	}
	if err := s.saveRecordIdentity(rec); err != nil {
		log.Printf("[record] the record identity's tip could not be kept outside the database: %v", err)
	}
	if witnesses, toad, err := keeper.WitnessConfig(rec.AID); err == nil {
		s.witness(rec.AID, kept, witnesses, toad)
	}
	return true, nil
}

func sortConversations(cs []anchoredConversation) {
	for i := 1; i < len(cs); i++ {
		for j := i; j > 0 && cs[j].ID < cs[j-1].ID; j-- {
			cs[j], cs[j-1] = cs[j-1], cs[j]
		}
	}
}

// noteRecorded counts one recorded message, anchoring once enough have been.
func (s *CoreServer) noteRecorded() {
	if s.record.recorded.Add(1) >= int64(anchorEvery) {
		s.record.recorded.Store(0)
		go func() {
			if _, err := s.anchorRecord(); err != nil {
				log.Printf("[record] anchoring: %v", err)
			}
		}()
	}
}

// anchorTick is how often the record is anchored: the interval, or half the
// time a quiet conversation takes to close if that is sooner, so the last
// entry of a conversation is anchored before it closes.
func anchorTick() time.Duration {
	if half := conversation.IdleClose / 2; half < anchorInterval {
		return half
	}
	return anchorInterval
}

// keepAnchoring anchors the record every anchorTick until stop closes.
func (s *CoreServer) keepAnchoring(stop <-chan struct{}) {
	t := time.NewTicker(anchorTick())
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.backfillControllerGrants()
			if _, err := s.anchorRecord(); err != nil && !errors.Is(err, errKeyElsewhere) {
				log.Printf("[record] anchoring: %v", err)
			}
		}
	}
}

// anchorCheck is what the anchors show about the record.
type anchorCheck struct {
	// Unavailable says why nothing is anchored, when nothing is.
	Unavailable string
	// AnchoredThrough is the newest log row an anchor fixes; Unanchored the
	// rows written since, and UnanchoredEntries the conversation entries no
	// anchor fixes yet.
	AnchoredThrough   int64
	Unanchored        int64
	UnanchoredEntries int
	// External reports whether the record identity names witnesses, so that
	// receipted anchors are held outside this Identity Agent too.
	// WitnessedThrough is the newest log row fixed by an anchor its witnesses
	// have receipted; AwaitingWitnesses the anchors not yet receipted enough.
	External          bool
	WitnessedThrough  int64
	AwaitingWitnesses int
	// WitnessTip is the newest event of the record identity's key log that a
	// witness, asked now, confirms holding; WitnessesAnswered how many did.
	// Where none answers, what the check found is this Identity Agent's word
	// alone.
	WitnessTip        int
	WitnessesAnswered int
	// BrokenAt is the place in the record identity's key log where the record
	// first stops holding, and Why says what failed. Zero when it holds.
	BrokenAt int
	Why      string
}

// checkAnchors checks the record against its anchors, with the record
// identity's key log as the authority.
func (s *CoreServer) checkAnchors() (anchorCheck, error) {
	var out anchorCheck
	if s.DataStore == nil || s.SandboxManager == nil || s.SandboxManager.Store() == nil {
		return out, nil
	}
	rows := s.SandboxManager.Store()
	heads := map[string]conversation.Conversation{}
	convs, cerr := s.conversations()
	if cerr == nil {
		if h, err := convs.Heads(); err == nil {
			heads = h
		}
	}
	unanchored := func(through int64, anchored map[string]int) (anchorCheck, error) {
		n, err := rows.RowsAfter(through)
		out.Unanchored = n
		for id, c := range heads {
			out.UnanchoredEntries += c.Seq - anchored[id]
		}
		return out, err
	}

	owner, err := s.DataStore.GetIdentity()
	if err != nil || owner == nil {
		return out, nil
	}
	approved, err := s.approvedRecordIdentities(owner.AID)
	if err != nil {
		return out, err
	}
	rec, made := s.loadRecordIdentity()
	if !made || rec.Pending {
		latest, err := s.DataStore.GetLatestRecordAnchor()
		if err != nil {
			return out, err
		}
		if len(approved) > 0 || latest != nil {
			out.BrokenAt, out.Why = -1, "this identity approved a record identity, or anchored its record, and the record identity's record here is gone"
			return unanchored(0, map[string]int{})
		}
		switch {
		case !s.anchorsItsRecord():
			out.Unavailable = "this Identity Agent anchors its record once it is an organisation's or holds an AI agent"
		case func() bool { _, err := s.identitySigningSeed(); return err != nil }():
			out.Unavailable = "the identity's key is held on another device, and nothing is anchored here"
		default:
			out.Unavailable = "nothing has been anchored yet"
		}
		return unanchored(0, map[string]int{})
	}
	broken := func(at int, why string) (anchorCheck, error) {
		out.BrokenAt, out.Why = at, why
		if at == 0 {
			out.BrokenAt = -1
		}
		return out, nil
	}

	// The record identity: its key log verifies, it was delegated by this
	// identity, and this identity's key log approves exactly its inception.
	events, err := s.DataStore.GetEvents(rec.AID)
	if err != nil {
		return out, err
	}
	if len(events) == 0 {
		return broken(0, "the record identity's key log is gone")
	}
	in := drivers.ValidateKELInput{AID: rec.AID}
	kel := make([]map[string]interface{}, 0, len(events))
	for _, ev := range events {
		raw, _ := base64.StdEncoding.DecodeString(ev.RawBytesB64)
		in.RawEvents = append(in.RawEvents, raw)
		in.CesrSignatures = append(in.CesrSignatures, ev.CesrSignature)
		var parsed map[string]interface{}
		_ = json.Unmarshal(raw, &parsed)
		kel = append(kel, parsed)
	}
	if got, err := drivers.ValidateKELFromBytes(in); err != nil || !got.KelVerified {
		return broken(0, "the record identity's key log does not verify")
	}
	if len(approved) != 1 || approved[0] != rec.AID {
		return broken(0, fmt.Sprintf("this identity approved %d record identities, where there must be exactly this one", len(approved)))
	}
	dip := kel[0]
	dipSAID, _ := dip["d"].(string)
	if !delegatedBy(dip, owner.AID, rec.AID) {
		return broken(0, "the record identity was not delegated by this identity")
	}
	if !approves(s.DataStore, owner.AID, rec.AID, dipSAID) {
		return broken(0, "this identity's key log does not approve the record identity")
	}
	// The tip kept outside the database must still be in the key log: the
	// newest anchors cannot be emptied out of the database unnoticed.
	keys := stringsOf(dip["k"])
	if len(keys) == 0 {
		return broken(0, "the record identity names no key")
	}
	if pub, err := login.DecodeVerkey(keys[0]); err != nil {
		return broken(0, "the record identity's key is unreadable")
	} else if ok, err := login.VerifyString(tipMessage(rec), rec.TipSig, pub); err != nil || !ok {
		return broken(rec.TipSN, "the tip kept outside the database is not signed by the record identity")
	}
	if rec.TipSN >= len(kel) || kel[rec.TipSN]["d"] != rec.TipSAID {
		return broken(rec.TipSN, "the record identity's key log is shorter than the tip last anchored")
	}

	// Ask the witnesses how far they hold the record identity's key log. One
	// holding more than this Identity Agent has, or something else at the same
	// place, is the record trimmed or rewritten.
	out.WitnessTip = -1
	if ws := stringsOf(dip["b"]); len(ws) > 0 && s.WitnessService != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		held := s.WitnessService.KelHeldBy(ctx, rec.AID, ws)
		cancel()
		for _, tip := range held {
			out.WitnessesAnswered++
			if tip.SN >= len(kel) || kel[tip.SN]["d"] != tip.SAID {
				return broken(tip.SN, "a witness holds the record identity's key log further, or otherwise, than this Identity Agent does")
			}
			if tip.SN > out.WitnessTip {
				out.WitnessTip = tip.SN
			}
		}
	}

	anchors, err := s.DataStore.GetRecordAnchors()
	if err != nil {
		return out, err
	}
	bySeq := map[int]store.RecordAnchor{}
	for _, a := range anchors {
		bySeq[a.Seq] = a
	}
	witnesses, toad := stringsOf(dip["b"]), thresholdOf(dip["bt"])
	out.External = len(witnesses) > 0
	anchoredSeq := map[string]int{}
	for sn := 1; sn < len(kel); sn++ {
		ev := kel[sn]
		said, _ := ev["d"].(string)
		a, ok := bySeq[sn]
		switch {
		case ev["t"] != "ixn":
			return broken(sn, "the record identity's key log holds something other than anchors")
		case !ok:
			return broken(sn, "the record identity's key log seals an anchoring whose statement is gone")
		case a.SAID != said || !sealsDigest(ev, a.Digest):
			return broken(sn, "the anchoring's statement is not the one its key log seals")
		}
		delete(bySeq, sn)
		if d, _ := iacrypto.Blake3QB64([]byte(a.Statement)); d != a.Digest {
			return broken(sn, "what was anchored no longer digests to its seal")
		}
		var st anchorStatement
		if err := json.Unmarshal([]byte(a.Statement), &st); err != nil {
			return broken(sn, "what was anchored is unreadable")
		}
		if h, there, err := rows.RowHash(st.Log.Row); err != nil {
			return out, err
		} else if st.Log.Row > 0 && (!there || h != st.Log.Head) {
			return broken(sn, fmt.Sprintf("log row %d, which an anchor fixes, has been removed or changed", st.Log.Row))
		}
		for _, c := range st.Conversations {
			if cerr != nil {
				return broken(sn, "the conversations an anchor fixes cannot be read")
			}
			e, err := convs.EntryAt(c.ID, c.Seq)
			if err != nil || e.Hash != c.Head {
				return broken(sn, fmt.Sprintf("entry %d of conversation %s, which an anchor fixes, has been removed or changed", c.Seq, c.ID))
			}
			if c.Seq > anchoredSeq[c.ID] {
				anchoredSeq[c.ID] = c.Seq
			}
		}
		if st.Log.Row > out.AnchoredThrough {
			out.AnchoredThrough = st.Log.Row
		}
		if out.External {
			if witnessedEnough(s.DataStore, said, witnesses, toad) {
				out.WitnessedThrough = out.AnchoredThrough
			} else {
				out.AwaitingWitnesses++
			}
		}
	}
	for sn := range bySeq {
		return broken(sn, "an anchoring is not sealed in the record identity's key log")
	}
	return unanchored(out.AnchoredThrough, anchoredSeq)
}

// delegatedBy reports whether an inception is the delegated inception of aid
// by delegator.
func delegatedBy(dip map[string]interface{}, delegator, aid string) bool {
	return dip["t"] == "dip" && dip["di"] == delegator && dip["i"] == aid
}

// approves reports whether the delegator's stored key log seals exactly this
// delegated inception.
func approves(ds store.Store, delegator, aid, dipSAID string) bool {
	events, err := ds.GetEvents(delegator)
	if err != nil {
		return false
	}
	for _, ev := range events {
		raw, _ := base64.StdEncoding.DecodeString(ev.RawBytesB64)
		var parsed struct {
			A []map[string]interface{} `json:"a"`
		}
		if json.Unmarshal(raw, &parsed) != nil {
			continue
		}
		for _, seal := range parsed.A {
			if seal["i"] == aid && seal["s"] == "0" && seal["d"] == dipSAID {
				return true
			}
		}
	}
	return false
}

// sealsDigest reports whether an interaction's seals include digest.
func sealsDigest(ev map[string]interface{}, digest string) bool {
	seals, _ := ev["a"].([]interface{})
	for _, raw := range seals {
		if seal, ok := raw.(map[string]interface{}); ok && seal["d"] == digest {
			return true
		}
	}
	return false
}

// witnessedEnough reports whether enough of the designated witnesses have
// returned a receipt for an event that verifies against their keys.
func witnessedEnough(ds store.Store, eventSAID string, witnesses []string, toad int) bool {
	receipts, err := ds.GetWitnessReceipts(eventSAID)
	if err != nil {
		return false
	}
	designated := map[string]bool{}
	for _, w := range witnesses {
		designated[w] = true
	}
	seen := map[string]bool{}
	for _, r := range receipts {
		if designated[r.WitnessAID] && !seen[r.WitnessAID] && drivers.VerifyReceipt(r.WitnessAID, eventSAID, r.CesrSignature) == nil {
			seen[r.WitnessAID] = true
		}
	}
	need := toad
	if need <= 0 {
		need = len(witnesses)
	}
	return len(seen) >= need
}

func thresholdOf(v interface{}) int {
	s, _ := v.(string)
	n, _ := strconv.ParseInt(s, 16, 64)
	return int(n)
}
