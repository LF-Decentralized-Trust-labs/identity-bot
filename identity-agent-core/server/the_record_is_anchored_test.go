package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/witness"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
	"identity-agent-core/login"
	"identity-agent-core/permission"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// recordWorld is an organisation that holds its own key, with a signed log.
func recordWorld(t *testing.T) *CoreServer {
	t.Helper()
	s, _ := grantWorld(t)
	s.DeclaredEntityType = "organization"
	s.logForTest(t, s.DataDir)
	s.vaultForTest(s.DataDir)
	s.ActivityLog.SetEventSigner(&invocationSigner{s: s})
	return s
}

func writeRows(t *testing.T, s *CoreServer, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if s.ActivityLog.RecordGovernanceEvent(permission.CallerContext{CallerAID: "EAgent", Reason: "test"}, "test.event", "ok") == 0 {
			t.Fatal("a row was not written")
		}
	}
}

// The log's head is anchored in a record identity approved in the
// organisation's key log, so removing the newest rows, which no later row
// names, is caught; what was written after the last anchoring is reported as
// not yet anchored rather than as checked.
func TestTheNewestRowsCannotBeQuietlyRemovedOnceAnchored(t *testing.T) {
	s := recordWorld(t)
	writeRows(t, s, 3)
	if anchored, err := s.anchorRecord(); err != nil || !anchored {
		t.Fatalf("anchoring: %v %v", anchored, err)
	}
	if anchored, _ := s.anchorRecord(); anchored {
		t.Fatal("an anchoring was made with nothing new to anchor")
	}

	rec, ok := s.loadRecordIdentity()
	if !ok {
		t.Fatal("no record identity was made")
	}
	owner, _ := s.DataStore.GetIdentity()
	rootEvents, _ := s.DataStore.GetEvents(owner.AID)
	approved := false
	for _, ev := range rootEvents {
		if ev.EventType == "ixn" && containsSealFor(t, ev.RawBytesB64, rec.AID) {
			approved = true
		}
	}
	if !approved {
		t.Fatal("the organisation's key log does not approve the record identity")
	}

	got := chainSays(t, s)
	row, _, _ := s.ActivityLog.Head()
	if got["intact"] != true || got["anchored_through"] != float64(row) || got["unanchored_rows"] != float64(0) {
		t.Fatalf("after anchoring the log reads %v", got)
	}

	writeRows(t, s, 1)
	if got := chainSays(t, s); got["intact"] != true || got["unanchored_rows"] != float64(1) {
		t.Fatalf("a row written after the anchoring is not reported as unanchored: %v", got)
	}

	// Remove the newest rows, the anchored one among them. No row names them,
	// so only the anchor can tell.
	db := s.ActivityLog.DB()
	if _, err := db.Exec(`DELETE FROM invocation_log WHERE id >= ?`, row); err != nil {
		t.Fatal(err)
	}
	if got := chainSays(t, s); got["intact"] != false || got["anchor_broken_at"] == nil {
		t.Fatalf("removing the newest rows went unnoticed: %v", got)
	}
}

func containsSealFor(t *testing.T, rawB64, aid string) bool {
	t.Helper()
	raw, _ := base64.StdEncoding.DecodeString(rawB64)
	var ev struct {
		A []map[string]interface{} `json:"a"`
	}
	_ = json.Unmarshal(raw, &ev)
	for _, seal := range ev.A {
		if seal["i"] == aid {
			return true
		}
	}
	return false
}

// After a restart the record identity is reloaded from what was kept, and the
// next anchoring chains to the last: its key log still verifies end to end.
func TestAnchoringCarriesOnAfterARestart(t *testing.T) {
	s := recordWorld(t)
	writeRows(t, s, 2)
	if _, err := s.anchorRecord(); err != nil {
		t.Fatal(err)
	}
	s.KeriDriver = keriengine.New()
	s.engineSigns()
	s.reloadKeyLogs()
	writeRows(t, s, 2)
	if anchored, err := s.anchorRecord(); err != nil || !anchored {
		t.Fatalf("anchoring after a restart: %v %v", anchored, err)
	}
	rec, _ := s.loadRecordIdentity()
	events, _ := s.DataStore.GetEvents(rec.AID)
	in := drivers.ValidateKELInput{AID: rec.AID}
	for _, ev := range events {
		raw, _ := base64.StdEncoding.DecodeString(ev.RawBytesB64)
		in.RawEvents = append(in.RawEvents, raw)
		in.CesrSignatures = append(in.CesrSignatures, ev.CesrSignature)
	}
	if got, err := drivers.ValidateKELFromBytes(in); err != nil || !got.KelVerified || len(events) != 3 {
		t.Fatalf("the record identity's key log after a restart: %d events, %v %v", len(events), err, got)
	}
	if got := chainSays(t, s); got["intact"] != true {
		t.Fatalf("the log does not hold after anchoring across a restart: %v", got)
	}
}

// Enough recorded messages anchor the record without waiting for the interval.
func TestEnoughMessagesAnchorTheRecord(t *testing.T) {
	s := recordWorld(t)
	anchorAfter(t, 3)
	writeRows(t, s, 1)
	for i := 0; i < 3; i++ {
		s.noteRecorded()
	}
	for i := 0; i < 100; i++ {
		if anchors, _ := s.DataStore.GetRecordAnchors(); len(anchors) == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("recording enough messages did not anchor the record")
}

// The record is anchored on its interval while the server runs, and stops
// being anchored when it stops.
func TestTheRecordIsAnchoredOnItsInterval(t *testing.T) {
	s := recordWorld(t)
	anchorAtLeastEvery(t, 20*time.Millisecond)
	writeRows(t, s, 1)
	stop := make(chan struct{})
	go s.keepAnchoring(stop)
	defer close(stop)
	for i := 0; i < 100; i++ {
		if anchors, _ := s.DataStore.GetRecordAnchors(); len(anchors) == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the record was not anchored on its interval")
}

// Where the identity's key is not held here, nothing is written into its key
// log: the record identity is not approved, and the record is not anchored.
func TestNothingIsWrittenIntoALogWhoseKeyIsElsewhere(t *testing.T) {
	s := recordWorld(t)
	writeRows(t, s, 1)
	owner, _ := s.DataStore.GetIdentity()
	before, _ := s.DataStore.GetEvents(owner.AID)
	// The identity's key is another device's: what it published is not what
	// this Identity Agent derives.
	elsewhere, _ := keri.GenerateSigner(true)
	owner.PublicKey, _ = elsewhere.PublicKey()
	if err := s.DataStore.SaveIdentity(*owner); err != nil {
		t.Fatal(err)
	}
	if _, err := s.identitySigningSeed(); err == nil {
		t.Fatal("the key still reads as held here")
	}
	if anchored, _ := s.anchorRecord(); anchored {
		t.Fatal("the record was anchored under a key this Identity Agent does not hold")
	}
	if got := chainSays(t, s); got["anchoring_unavailable"] == nil || got["unanchored_rows"] != float64(1) {
		t.Fatalf("a record nothing can anchor is not reported so: %v", got)
	}
	if after, _ := s.DataStore.GetEvents(owner.AID); len(after) != len(before) {
		t.Fatal("an event was written into a key log whose key is elsewhere")
	}
}

// anchoredTwice is a record anchored over rows 1-3, then over rows 4-5.
func anchoredTwice(t *testing.T) (*CoreServer, int64) {
	t.Helper()
	s := recordWorld(t)
	writeRows(t, s, 3)
	if ok, err := s.anchorRecord(); err != nil || !ok {
		t.Fatalf("first anchoring: %v %v", ok, err)
	}
	first, _, _ := s.ActivityLog.Head()
	writeRows(t, s, 2)
	if ok, err := s.anchorRecord(); err != nil || !ok {
		t.Fatalf("second anchoring: %v %v", ok, err)
	}
	if got := chainSays(t, s); got["intact"] != true {
		t.Fatalf("the record does not hold before anything is touched: %v", got)
	}
	return s, first
}

func mustBreak(t *testing.T, s *CoreServer, what string) {
	t.Helper()
	if got := chainSays(t, s); got["intact"] != false || got["anchor_broken_at"] == nil {
		t.Fatalf("%s went unnoticed: %v", what, got)
	}
}

// Removing the newest anchoring and every row after the first leaves the
// record identity's key log sealing a statement that is gone.
func TestRemovingTheNewestAnchorAndItsRowsIsCaught(t *testing.T) {
	s, first := anchoredTwice(t)
	db := recordDB(t, s)
	if _, err := db.Exec(`DELETE FROM record_anchors WHERE seq = (SELECT MAX(seq) FROM record_anchors)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActivityLog.DB().Exec(`DELETE FROM invocation_log WHERE id > ?`, first); err != nil {
		t.Fatal(err)
	}
	mustBreak(t, s, "removing the newest anchoring and the rows it fixed")
}

// Removing the newest anchoring together with its interaction leaves the key
// log shorter than the tip kept outside the database.
func TestTrimmingTheRecordIdentitysKeyLogIsCaught(t *testing.T) {
	s, first := anchoredTwice(t)
	rec, _ := s.loadRecordIdentity()
	db := recordDB(t, s)
	db.Exec(`DELETE FROM record_anchors WHERE seq = (SELECT MAX(seq) FROM record_anchors)`)
	if _, err := db.Exec(`DELETE FROM kel WHERE aid = ? AND seq_num = (SELECT MAX(seq_num) FROM kel WHERE aid = ?)`, rec.AID, rec.AID); err != nil {
		t.Fatal(err)
	}
	s.ActivityLog.DB().Exec(`DELETE FROM invocation_log WHERE id > ?`, first)
	mustBreak(t, s, "trimming the record identity's key log")
}

// A statement changed after it was anchored no longer digests to its seal.
func TestAChangedStatementIsCaught(t *testing.T) {
	s, _ := anchoredTwice(t)
	db := recordDB(t, s)
	// Still a statement that names real rows; only what was digested changed.
	if _, err := db.Exec(`UPDATE record_anchors SET statement = replace(statement, '"at":"', '"at":"1') WHERE seq = 1`); err != nil {
		t.Fatal(err)
	}
	mustBreak(t, s, "a changed statement")
}

// A statement and digest both replaced, consistently with each other, are not
// what the key log seals.
func TestAStatementTheKeyLogDoesNotSealIsCaught(t *testing.T) {
	s, _ := anchoredTwice(t)
	db := recordDB(t, s)
	// A statement naming the same, real rows, with a digest that matches it,
	// but not the one the key log sealed.
	var st string
	db.QueryRow(`SELECT statement FROM record_anchors WHERE seq = 1`).Scan(&st)
	st = strings.Replace(st, `"at":"`, `"at":"1`, 1)
	d, _ := iacrypto.Blake3QB64([]byte(st))
	if _, err := db.Exec(`UPDATE record_anchors SET statement = ?, digest = ? WHERE seq = 1`, st, d); err != nil {
		t.Fatal(err)
	}
	mustBreak(t, s, "a statement the key log does not seal")
}

// A record identity's key log that has been altered does not verify.
func TestAnAlteredRecordKeyLogIsCaught(t *testing.T) {
	s, _ := anchoredTwice(t)
	rec, _ := s.loadRecordIdentity()
	db := recordDB(t, s)
	// The event as it was, signed by a key that is not the record identity's.
	var b64 string
	db.QueryRow(`SELECT raw_bytes_b64 FROM kel WHERE aid = ? AND seq_num = 1`, rec.AID).Scan(&b64)
	raw, _ := base64.StdEncoding.DecodeString(b64)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := signEventBytes(raw, other.Seed())
	if _, err := db.Exec(`UPDATE kel SET cesr_signature = ? WHERE aid = ? AND seq_num = 1`, forged, rec.AID); err != nil {
		t.Fatal(err)
	}
	mustBreak(t, s, "an altered record key log")
}

// A record identity this identity's key log does not approve is not one.
func TestARecordIdentityWithoutItsApprovalIsCaught(t *testing.T) {
	s, _ := anchoredTwice(t)
	rec, _ := s.loadRecordIdentity()
	owner, _ := s.DataStore.GetIdentity()
	events, _ := s.DataStore.GetEvents(owner.AID)
	db := recordDB(t, s)
	for _, ev := range events {
		if containsSealFor(t, ev.RawBytesB64, rec.AID) {
			if _, err := db.Exec(`DELETE FROM kel WHERE aid = ? AND seq_num = ?`, owner.AID, ev.SequenceNumber); err != nil {
				t.Fatal(err)
			}
		}
	}
	mustBreak(t, s, "a record identity nobody approved")
}

// With nothing anchored every row is counted unanchored and the report says
// why, rather than calling the record checked.
func TestNothingAnchoredIsNeverReportedAsChecked(t *testing.T) {
	s := recordWorld(t)
	writeRows(t, s, 4)
	got := chainSays(t, s)
	if got["anchoring_unavailable"] == nil || got["unanchored_rows"] != float64(4) || got["anchored_through"] != float64(0) {
		t.Fatalf("a record with no anchors reads as %v", got)
	}
}

// An individual's Identity Agent with no AI agent writes nothing into its key
// log on its own.
func TestAnIndividualWithNoAIAgentAnchorsNothing(t *testing.T) {
	s := recordWorld(t)
	s.DeclaredEntityType = "individual"
	writeRows(t, s, 2)
	owner, _ := s.DataStore.GetIdentity()
	before, _ := s.DataStore.GetEvents(owner.AID)
	if ok, err := s.anchorRecord(); ok || err != nil {
		t.Fatalf("an individual with no AI agent anchored: %v %v", ok, err)
	}
	if after, _ := s.DataStore.GetEvents(owner.AID); len(after) != len(before) {
		t.Fatal("an individual's key log was written to unasked")
	}
}

// A record identity left pending by a stop is finished if its inception was
// kept, and removed if not.
func TestARecordIdentityLeftPartlyMadeIsRepaired(t *testing.T) {
	s := recordWorld(t)
	if err := s.saveRecordIdentity(recordIdentityRecord{AID: "Enever-kept", Index: 10000001, Pending: true}); err != nil {
		t.Fatal(err)
	}
	s.repairRecordIdentity()
	if _, ok := s.loadRecordIdentity(); ok {
		t.Fatal("a record identity never kept was left in place")
	}
	writeRows(t, s, 1)
	if ok, err := s.anchorRecord(); err != nil || !ok {
		t.Fatalf("anchoring after the repair: %v %v", ok, err)
	}
	rec, _ := s.loadRecordIdentity()
	rec.Pending = true
	s.saveRecordIdentity(rec)
	s.repairRecordIdentity()
	if got, ok := s.loadRecordIdentity(); !ok || got.Pending {
		t.Fatal("a record identity whose inception was kept was not finished")
	}
}

// With no witnesses named, the report says the anchors are not held outside.
func TestAnchorsWithNoWitnessesSaySo(t *testing.T) {
	s := recordWorld(t)
	writeRows(t, s, 1)
	s.anchorRecord()
	if got := chainSays(t, s); got["anchoring_external"] != false {
		t.Fatalf("anchors with no witnesses read as held outside: %v", got)
	}
}

// A receipt counts only from a witness the record identity names, verified
// against that witness's key, once per witness, and enough of them.
func TestOnlyNamedWitnessesReceiptsCount(t *testing.T) {
	s := recordWorld(t)
	keys := make([]ed25519.PrivateKey, 3)
	names := make([]string, 3)
	for i := range keys {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		keys[i], names[i] = priv, iacrypto.NonTransferableAIDQB64(pub)
	}
	said := "Ethe-event"
	sign := func(i int) string {
		sig, _ := login.SignString(said, keys[i].Seed())
		return sig
	}
	s.DataStore.SaveWitnessReceipt(store.WitnessReceiptRecord{EventSAID: said, WitnessAID: names[0], CesrSignature: sign(0)})
	if witnessedEnough(s.DataStore, said, names, 2) {
		t.Fatal("one receipt met a threshold of two")
	}
	s.DataStore.SaveWitnessReceipt(store.WitnessReceiptRecord{EventSAID: said, WitnessAID: names[1], CesrSignature: sign(2)})
	if witnessedEnough(s.DataStore, said, names, 2) {
		t.Fatal("a receipt signed by another witness's key counted")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	stranger := iacrypto.NonTransferableAIDQB64(pub)
	strangerSig, _ := login.SignString(said, priv.Seed())
	s.DataStore.SaveWitnessReceipt(store.WitnessReceiptRecord{EventSAID: said, WitnessAID: stranger, CesrSignature: strangerSig})
	if witnessedEnough(s.DataStore, said, names, 2) {
		t.Fatal("a receipt from a witness the record identity does not name counted")
	}
	s.DataStore.SaveWitnessReceipt(store.WitnessReceiptRecord{EventSAID: said, WitnessAID: names[2], CesrSignature: sign(2)})
	if !witnessedEnough(s.DataStore, said, names, 2) {
		t.Fatal("two named witnesses' receipts did not meet a threshold of two")
	}
}

// An anchoring the record identity's key log does not seal is not one.
func TestAnAnchorNobodySealedIsCaught(t *testing.T) {
	s, _ := anchoredTwice(t)
	db := recordDB(t, s)
	if _, err := db.Exec(`INSERT INTO record_anchors (seq, said, statement, digest, created_at) SELECT 99, said, statement, digest, created_at FROM record_anchors WHERE seq = 1`); err != nil {
		t.Fatal(err)
	}
	mustBreak(t, s, "an anchoring nobody sealed")
}

// A record identity is the delegated identity it claims to be, of this
// identity, and of nobody else.
func TestARecordIdentityIsDelegatedByThisIdentity(t *testing.T) {
	dip := map[string]interface{}{"t": "dip", "di": "EOrg", "i": "ERec"}
	if !delegatedBy(dip, "EOrg", "ERec") {
		t.Fatal("the organisation's own delegation was refused")
	}
	for _, bad := range []map[string]interface{}{
		{"t": "icp", "di": "EOrg", "i": "ERec"},
		{"t": "dip", "di": "EOther", "i": "ERec"},
		{"t": "dip", "di": "EOrg", "i": "EElse"},
	} {
		if delegatedBy(bad, "EOrg", "ERec") {
			t.Fatalf("%v was taken as the organisation's delegation of the record identity", bad)
		}
	}
}

// Where the organisation names witnesses, the record identity names the same
// ones, and an anchoring counts as held outside only once enough of them have
// receipted it.
func TestAnchorsAreHeldOutsideOnceTheirWitnessesReceiptThem(t *testing.T) {
	keys := make([]ed25519.PrivateKey, 3)
	names := make([]string, 3)
	for i := range keys {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		keys[i], names[i] = priv, iacrypto.NonTransferableAIDQB64(pub)
	}
	s, _ := foundedWith(t, agentWithDerivedIdentity(t), names, 2)
	s.DeclaredEntityType = "organization"
	s.logForTest(t, s.DataDir)
	s.vaultForTest(s.DataDir)
	s.ActivityLog.SetEventSigner(&invocationSigner{s: s})
	writeRows(t, s, 2)
	if ok, err := s.anchorRecord(); err != nil || !ok {
		t.Fatalf("anchoring: %v %v", ok, err)
	}
	rec, _ := s.loadRecordIdentity()
	events, _ := s.DataStore.GetEvents(rec.AID)
	var dip struct {
		B  []string `json:"b"`
		Bt string   `json:"bt"`
	}
	json.Unmarshal([]byte(events[0].EventJSON), &dip)
	if len(dip.B) != 3 || dip.Bt != "2" {
		t.Fatalf("the record identity does not name the organisation's witnesses: %+v", dip)
	}
	got := chainSays(t, s)
	if got["anchoring_external"] != true || got["awaiting_witnesses"] != float64(1) || got["witnessed_through"] != float64(0) {
		t.Fatalf("an anchoring nobody has receipted reads as %v", got)
	}
	var ixn map[string]interface{}
	json.Unmarshal([]byte(events[1].EventJSON), &ixn)
	said, _ := ixn["d"].(string)
	for i := 0; i < 2; i++ {
		sig, _ := login.SignString(said, keys[i].Seed())
		s.DataStore.SaveWitnessReceipt(store.WitnessReceiptRecord{EventSAID: said, WitnessAID: names[i], CesrSignature: sig})
	}
	got = chainSays(t, s)
	if got["awaiting_witnesses"] != float64(0) || got["witnessed_through"] != got["anchored_through"] {
		t.Fatalf("an anchoring two of its witnesses receipted reads as %v", got)
	}
}

// The reviewer's case: remove the record identity's file, the anchors and the
// newest rows. The record is reported broken, never "nothing anchored", and no
// second record identity is made to anchor the shortened log.
func TestALostRecordIdentityIsNeverReplacedQuietly(t *testing.T) {
	s, first := anchoredTwice(t)
	owner, _ := s.DataStore.GetIdentity()
	before, _ := s.DataStore.GetEvents(owner.AID)
	if err := os.Remove(filepath.Join(s.DataDir, recordIdentityFile)); err != nil {
		t.Fatal(err)
	}
	db := recordDB(t, s)
	db.Exec(`DELETE FROM record_anchors`)
	s.ActivityLog.DB().Exec(`DELETE FROM invocation_log WHERE id > ?`, first)
	mustBreak(t, s, "a lost record identity")
	writeRows(t, s, 1)
	if _, err := s.anchorRecord(); !errors.Is(err, errRecordGone) {
		t.Fatalf("anchoring with the record identity's record gone: %v", err)
	}
	if after, _ := s.DataStore.GetEvents(owner.AID); len(after) != len(before) {
		t.Fatal("a second record identity was approved")
	}
	if approved, _ := s.approvedRecordIdentities(owner.AID); len(approved) != 1 {
		t.Fatalf("the organisation approves %d record identities", len(approved))
	}
	mustBreak(t, s, "a lost record identity, after trying to anchor again")
}

// With only the anchors gone and the file in place, the record identity's
// key log still names statements that are gone.
func TestAnchorsGoneWithTheFileInPlaceAreCaught(t *testing.T) {
	s, _ := anchoredTwice(t)
	recordDB(t, s).Exec(`DELETE FROM record_anchors`)
	mustBreak(t, s, "the anchors removed")
}

// The tip kept outside the database cannot be lowered without the record
// identity's key.
func TestALoweredTipIsCaught(t *testing.T) {
	s, _ := anchoredTwice(t)
	rec, _ := s.loadRecordIdentity()
	events, _ := s.DataStore.GetEvents(rec.AID)
	var first map[string]interface{}
	json.Unmarshal([]byte(events[1].EventJSON), &first)
	rec.TipSN, rec.TipSAID = 1, first["d"].(string)
	s.saveRecordIdentity(rec)
	mustBreak(t, s, "a tip lowered without the record identity's key")
}

// With the record identity's file gone and its approval no longer found, the
// anchors left behind still stop a new one being made over them.
func TestNoRecordIdentityIsMadeOverAnchorsLeftBehind(t *testing.T) {
	s, _ := anchoredTwice(t)
	rec, _ := s.loadRecordIdentity()
	owner, _ := s.DataStore.GetIdentity()
	events, _ := s.DataStore.GetEvents(owner.AID)
	db := recordDB(t, s)
	for _, ev := range events {
		if containsSealFor(t, ev.RawBytesB64, rec.AID) {
			db.Exec(`DELETE FROM kel WHERE aid = ? AND seq_num = ?`, owner.AID, ev.SequenceNumber)
		}
	}
	os.Remove(filepath.Join(s.DataDir, recordIdentityFile))
	writeRows(t, s, 1)
	if _, err := s.anchorRecord(); !errors.Is(err, errRecordGone) {
		t.Fatalf("a record identity was made over anchors left behind: %v", err)
	}
}

// Exactly one record identity: a second one this identity approved, on the
// record key but naming other witnesses, breaks the record.
func TestASecondRecordIdentityIsCaught(t *testing.T) {
	s, _ := anchoredTwice(t)
	rec, _ := s.loadRecordIdentity()
	owner, _ := s.DataStore.GetIdentity()
	seed, pub, nextPub, err := s.recordKeys(rec.Index)
	if err != nil {
		t.Fatal(err)
	}
	wpub, _, _ := ed25519.GenerateKey(rand.Reader)
	keeper := s.KeriDriver.(drivers.KELKeeper)
	if _, err := keeper.CreateDelegatedInceptionKept(pub, nextPub, "second", owner.AID, []string{iacrypto.NonTransferableAIDQB64(wpub)}, 1, func(k drivers.KELKeep) error {
		approval, dip, err := s.delegationRecords(owner.AID, k, pub, seed)
		if err != nil {
			return err
		}
		return s.DataStore.KeepEvents(approval, dip)
	}); err != nil {
		t.Fatal(err)
	}
	mustBreak(t, s, "a second record identity")
}

// The check asks the record identity's witnesses how far they hold its key
// log. Where they confirm what is here, it says so; where one holds more, the
// local log was trimmed, and the record is broken.
func TestTheWitnessesAreAskedForTheRecordsTip(t *testing.T) {
	keys := make([]ed25519.PrivateKey, 2)
	names := make([]string, 2)
	for i := range keys {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		keys[i], names[i] = priv, iacrypto.NonTransferableAIDQB64(pub)
	}
	s, _ := foundedWith(t, agentWithDerivedIdentity(t), names, 1)
	s.DeclaredEntityType = "organization"
	s.logForTest(t, s.DataDir)
	s.vaultForTest(s.DataDir)
	s.ActivityLog.SetEventSigner(&invocationSigner{s: s})
	sq := s.DataStore.(*store.SQLiteStore)
	s.WitnessService = witness.NewService(witness.NewSQLiteStore(sq.DB()), sq, s.KeriDriver, witness.BackendDesktop)
	for i, name := range names {
		aid := fmt.Sprintf("EWitness%d", i)
		s.DataStore.SaveContact(store.ContactRecord{AID: aid, OobiURL: "http://w" + fmt.Sprint(i) + ".test", Status: "active"})
		s.WitnessService.Store.SaveContactMeta(witness.ContactMeta{ContactAID: aid, WitnessKey: name})
	}
	var held []store.EventRecord
	answerAs := func(i int, url string) witness.TipAnswer { return witnessTip(url, held, keys[i], names[i]) }
	// Asked from several goroutines at once: the check asks every witness
	// together, and the witnessing worker asks too.
	var answerMu sync.Mutex
	answer := answerAs
	setAnswer := func(f func(int, string) witness.TipAnswer) {
		answerMu.Lock()
		answer = f
		answerMu.Unlock()
	}
	s.WitnessService.FetchTip = func(_ context.Context, url string) (witness.TipAnswer, error) {
		i := 0
		if strings.Contains(url, "w1.test") {
			i = 1
		}
		answerMu.Lock()
		defer answerMu.Unlock()
		return answer(i, url), nil
	}
	var postedMu sync.Mutex
	posted := map[string]bool{}
	s.WitnessService.PostEvent = func(_ context.Context, _ string, body []byte) (map[string]interface{}, error) {
		var req struct {
			AID string `json:"aid"`
		}
		json.Unmarshal(body, &req)
		postedMu.Lock()
		posted[req.AID] = true
		postedMu.Unlock()
		return nil, fmt.Errorf("offline")
	}
	writeRows(t, s, 2)
	if ok, err := s.anchorRecord(); err != nil || !ok {
		t.Fatalf("anchoring: %v %v", ok, err)
	}
	rec, _ := s.loadRecordIdentity()
	owner, _ := s.DataStore.GetIdentity()
	for i := 0; i < 100; i++ {
		postedMu.Lock()
		both := posted[owner.AID] && posted[rec.AID]
		postedMu.Unlock()
		if both {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	postedMu.Lock()
	if !posted[owner.AID] {
		t.Fatal("the organisation's approval of the record identity was not sent to its witnesses")
	}
	postedMu.Unlock()
	events, _ := s.DataStore.GetEvents(rec.AID)

	// Nobody answers: local only.
	got := chainSays(t, s)
	if got["witnesses_answered"] != float64(0) || got["witness_confirmed_tip"] != nil {
		t.Fatalf("with no witness answering the check reads %v", got)
	}
	// Both hold what is here.
	answerMu.Lock()
	held = events
	answerMu.Unlock()
	got = chainSays(t, s)
	if got["witnesses_answered"] != float64(2) || got["witness_confirmed_tip"] != float64(len(events)-1) || got["anchor_broken_at"] != nil {
		t.Fatalf("with the witnesses confirming the tip the check reads %v", got)
	}
	// An answer that does not check out is no answer: one signed by another
	// key, or one replayed from an earlier question.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	setAnswer(func(i int, url string) witness.TipAnswer {
		a := answerAs(i, url)
		a.Signature, _ = login.SignString(witness.TipStatement(a.AID, a.Nonce, a.SN, a.SAID), otherPriv.Seed())
		return a
	})
	if got := chainSays(t, s); got["witnesses_answered"] != float64(0) {
		t.Fatalf("a tip signed by another key was believed: %v", got)
	}
	replayed := map[int]witness.TipAnswer{}
	setAnswer(func(i int, url string) witness.TipAnswer {
		if a, ok := replayed[i]; ok {
			return a
		}
		replayed[i] = answerAs(i, url)
		return replayed[i]
	})
	chainSays(t, s)
	if got := chainSays(t, s); got["witnesses_answered"] != float64(0) {
		t.Fatalf("a replayed answer was believed: %v", got)
	}
	setAnswer(answerAs)
	// They hold one event more than is left here.
	writeRows(t, s, 1)
	if ok, err := s.anchorRecord(); err != nil || !ok {
		t.Fatalf("anchoring again: %v %v", ok, err)
	}
	events, _ = s.DataStore.GetEvents(rec.AID)
	answerMu.Lock()
	held = events
	answerMu.Unlock()
	last := events[len(events)-1]
	recordDB(t, s).Exec(`DELETE FROM kel WHERE aid = ? AND seq_num = ?`, rec.AID, last.SequenceNumber)
	recordDB(t, s).Exec(`DELETE FROM record_anchors WHERE seq = (SELECT MAX(seq) FROM record_anchors)`)
	var prior map[string]interface{}
	json.Unmarshal([]byte(events[len(events)-2].EventJSON), &prior)
	rec.TipSN, rec.TipSAID = last.SequenceNumber-1, prior["d"].(string)
	seed, _, _, _ := s.recordKeys(rec.Index)
	signTip(&rec, seed)
	s.saveRecordIdentity(rec)
	mustBreak(t, s, "a key log the witnesses hold further than is left here")
}

// The check never compares the witnesses with a key log an anchoring is part
// way through extending: anchoring and checking at once, with witnesses that
// hold exactly what has been appended, never reads as tampering.
func TestCheckingWhileAnchoringRaisesNoFalseAlarm(t *testing.T) {
	keys := make([]ed25519.PrivateKey, 1)
	names := make([]string, 1)
	for i := range keys {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		keys[i], names[i] = priv, iacrypto.NonTransferableAIDQB64(pub)
	}
	s, _ := foundedWith(t, agentWithDerivedIdentity(t), names, 1)
	s.DeclaredEntityType = "organization"
	s.logForTest(t, s.DataDir)
	s.vaultForTest(s.DataDir)
	s.ActivityLog.SetEventSigner(&invocationSigner{s: s})
	sq := s.DataStore.(*store.SQLiteStore)
	s.WitnessService = witness.NewService(witness.NewSQLiteStore(sq.DB()), sq, s.KeriDriver, witness.BackendDesktop)
	s.DataStore.SaveContact(store.ContactRecord{AID: "EWitness0", OobiURL: "http://w0.test", Status: "active"})
	s.WitnessService.Store.SaveContactMeta(witness.ContactMeta{ContactAID: "EWitness0", WitnessKey: names[0]})
	s.WitnessService.PostEvent = func(context.Context, string, []byte) (map[string]interface{}, error) {
		return nil, fmt.Errorf("offline")
	}
	writeRows(t, s, 2)
	if ok, err := s.anchorRecord(); err != nil || !ok {
		t.Fatalf("anchoring: %v %v", ok, err)
	}
	rec, _ := s.loadRecordIdentity()
	// The witness is slow to answer, and answers with whatever has been
	// appended by then, so an anchoring may land while the check waits.
	s.WitnessService.FetchTip = func(_ context.Context, url string) (witness.TipAnswer, error) {
		time.Sleep(5 * time.Millisecond)
		events, _ := s.DataStore.GetEvents(rec.AID)
		return witnessTip(url, events, keys[0], names[0]), nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 15; i++ {
			writeRows(t, s, 1)
			s.anchorRecord()
			time.Sleep(15 * time.Millisecond)
		}
	}()
	for {
		select {
		case <-done:
			return
		default:
		}
		c, err := s.checkAnchors()
		if err != nil {
			t.Fatal(err)
		}
		if c.BrokenAt != 0 || c.Why != "" {
			t.Fatalf("checking while anchoring read as tampering: %d %s", c.BrokenAt, c.Why)
		}
	}
}

// Places taken in the record pool by attempts that failed do not move the
// record identity: it is found, and the record checks, however many there were.
func TestFailedAttemptsDoNotMoveTheRecordIdentity(t *testing.T) {
	s := recordWorld(t)
	for i := 0; i < 40; i++ {
		if _, err := s.DataStore.AllocateNextRelationshipIndex("record"); err != nil {
			t.Fatal(err)
		}
	}
	writeRows(t, s, 2)
	if ok, err := s.anchorRecord(); err != nil || !ok {
		t.Fatalf("anchoring: %v %v", ok, err)
	}
	if got := chainSays(t, s); got["anchor_broken_at"] != nil {
		t.Fatalf("the record identity was not found after failed attempts: %v", got)
	}
}

// witnessTip is what a witness holding these events answers when asked at
// url: its tip, signed with its key together with the nonce it was asked with.
func witnessTip(url string, events []store.EventRecord, key ed25519.PrivateKey, name string) witness.TipAnswer {
	path, query, _ := strings.Cut(url, "?")
	aid := strings.TrimSuffix(path[strings.Index(path, "/witness/kel/")+len("/witness/kel/"):], "/tip")
	nonce := strings.TrimPrefix(query, "nonce=")
	a := witness.TipAnswer{AID: aid, Nonce: nonce, SN: -1, WitnessAID: name}
	if len(events) > 0 {
		raw, _ := base64.StdEncoding.DecodeString(events[len(events)-1].RawBytesB64)
		var last map[string]interface{}
		json.Unmarshal(raw, &last)
		a.SAID, _ = last["d"].(string)
		a.SN = events[len(events)-1].SequenceNumber
	}
	a.Signature, _ = login.SignString(witness.TipStatement(a.AID, a.Nonce, a.SN, a.SAID), key.Seed())
	return a
}

// End to end, with a real witness reached over HTTP: the witness agrees to
// witness for the organisation through the ordinary request, is brought up to
// date with the organisation's key log in order, takes the record identity on
// from the organisation's approval, receipts its anchorings, and confirms its
// tip when the check asks.
func TestARealWitnessWitnessesTheRecord(t *testing.T) {
	peer := startPeer(t, "witness")
	s, _ := foundedWith(t, agentWithDerivedIdentity(t), []string{peer.witnessKey}, 1)
	s.DeclaredEntityType = "organization"
	s.logForTest(t, s.DataDir)
	s.vaultForTest(s.DataDir)
	s.ActivityLog.SetEventSigner(&invocationSigner{s: s})
	sq := s.DataStore.(*store.SQLiteStore)
	s.WitnessService = witness.NewService(witness.NewSQLiteStore(sq.DB()), sq, s.KeriDriver, witness.BackendDesktop)
	s.DataStore.SaveContact(store.ContactRecord{AID: "EWitnessPeer", OobiURL: peer.base, Status: "accepted"})
	s.WitnessService.Store.SaveContactMeta(witness.ContactMeta{ContactAID: "EWitnessPeer", WitnessKey: peer.witnessKey})

	// The witness agrees to witness for the organisation, the ordinary way.
	owner, _ := s.DataStore.GetIdentity()
	peer.svc.Contacts.SaveContact(store.ContactRecord{AID: owner.AID, Status: "accepted", ContactCategory: "trusted", PublicKey: owner.PublicKey})
	if res := peer.svc.ProcessInboundRequest(context.Background(), signedWitnessRequest(t, s, peer.svc, owner.AID, true)); !res.Accepted {
		t.Fatalf("the witness did not agree to witness for the organisation: %s", res.Reason)
	}

	for i := 0; i < 2; i++ {
		writeRows(t, s, 2)
		if ok, err := s.anchorRecord(); err != nil || !ok {
			t.Fatalf("anchoring: %v %v", ok, err)
		}
	}
	rec, _ := s.loadRecordIdentity()
	events, _ := s.DataStore.GetEvents(rec.AID)
	ownerEvents, _ := s.DataStore.GetEvents(owner.AID)
	held := func(aid string) int {
		events, _ := peer.svc.Store.GetKelEvents(aid)
		return len(events)
	}
	for i := 0; i < 300 && (held(rec.AID) < len(events) || held(owner.AID) < len(ownerEvents)); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if held(owner.AID) != len(ownerEvents) {
		t.Fatalf("the witness holds %d of the organisation's %d events", held(owner.AID), len(ownerEvents))
	}
	if held(rec.AID) != len(events) {
		t.Fatalf("the witness holds %d of the record identity's %d events", held(rec.AID), len(events))
	}
	got := chainSays(t, s)
	for i := 0; i < 100 && got["witnessed_through"] != got["anchored_through"]; i++ {
		time.Sleep(20 * time.Millisecond)
		got = chainSays(t, s)
	}
	if got["witnesses_answered"] != float64(1) || got["witness_confirmed_tip"] != float64(len(events)-1) {
		t.Fatalf("the check does not report the witness confirming the tip: %v", got)
	}
	if got["anchor_broken_at"] != nil || got["witnessed_through"] != got["anchored_through"] {
		t.Fatalf("the record reads as %v", got)
	} // The witness hands back, over HTTP, an event it holds exactly as signed:
	// where an Identity Agent finds what the device holding the key signed.
	back := s.WitnessService.EventsHeldAt(context.Background(), owner.AID, 1, []string{peer.witnessKey})
	if len(back) != 1 || back[0].RawBytesB64 != ownerEvents[1].RawBytesB64 || back[0].CesrSignature != ownerEvents[1].CesrSignature {
		t.Fatalf("the witness handed back %+v", back)
	}
}

// Stopping while the witnessing worker runs ends it, with no race on the
// channel that tells it to stop.
func TestStoppingWhileWitnessingEndsTheWorker(t *testing.T) {
	s := recordWorld(t)
	s.anchorStopMu.Lock()
	s.anchorStop = make(chan struct{})
	s.anchorStopMu.Unlock()
	sq := s.DataStore.(*store.SQLiteStore)
	s.WitnessService = witness.NewService(witness.NewSQLiteStore(sq.DB()), sq, s.KeriDriver, witness.BackendDesktop)
	s.WitnessService.FetchTip = func(context.Context, string) (witness.TipAnswer, error) {
		return witness.TipAnswer{}, fmt.Errorf("offline")
	}
	owner, _ := s.DataStore.GetIdentity()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			s.witnessRecord(owner.AID, owner.AID, []string{"BWitness"}, 1)
		}
	}()
	s.anchorStopMu.Lock()
	close(s.anchorStop)
	s.anchorStop = nil
	s.anchorStopMu.Unlock()
	<-done
}

// A request to witness the identity's own log does not drop the record
// identity a pass is already due to send.
func TestWitnessingTheOwnLogKeepsTheRecordDue(t *testing.T) {
	s := recordWorld(t)
	sq := s.DataStore.(*store.SQLiteStore)
	s.WitnessService = witness.NewService(witness.NewSQLiteStore(sq.DB()), sq, s.KeriDriver, witness.BackendDesktop)
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	s.WitnessService.FetchTip = func(context.Context, string) (witness.TipAnswer, error) {
		<-hold
		return witness.TipAnswer{}, fmt.Errorf("offline")
	}
	s.witnessRecord("EOwner", "ERecord", []string{"BWitness"}, 1)
	s.witnessRecord("EOwner", "", []string{"BWitness"}, 1)
	s.witnessing.witnessMu.Lock()
	defer s.witnessing.witnessMu.Unlock()
	if s.witnessing.witnessJob.record != "ERecord" {
		t.Fatal("the record identity due to be witnessed was dropped")
	}
}

// A witness request that asks for the requester's delegates is recorded as
// covering them, and one that does not, as not.
func TestAWitnessRequestCarriesWhetherItCoversDelegates(t *testing.T) {
	for _, asks := range []bool{true, false} {
		s := recordWorld(t)
		sq := s.DataStore.(*store.SQLiteStore)
		s.WitnessService = witness.NewService(witness.NewSQLiteStore(sq.DB()), sq, s.KeriDriver, witness.BackendDesktop)
		owner, _ := s.DataStore.GetIdentity()
		// The requester is this identity, asking itself: what matters is
		// that the flag is carried, signed, through the route.
		s.DataStore.SaveContact(store.ContactRecord{AID: owner.AID, Status: "accepted", ContactCategory: "trusted", PublicKey: owner.PublicKey})
		req := signedWitnessRequest(t, s, s.WitnessService, owner.AID, asks)
		body := fmt.Sprintf(`{"requester_aid":%q,"backend_type":"desktop","covers_delegates":%v,"stamp":%q,"signature":%q}`,
			owner.AID, asks, req.Stamp, req.Signature)
		rec := httptest.NewRecorder()
		s.handleWitnessRequest(rec, httptest.NewRequest("POST", "/api/witness/request", strings.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("the request: %d %s", rec.Code, rec.Body.String())
		}
		if got := s.WitnessService.CoversDelegatesOf(owner.AID); got != asks {
			t.Fatalf("a signed request asking=%v is recorded as covering delegates=%v", asks, got)
		}
	}
}

// signedWitnessRequest is a witness request to to, signed as s's identity.
func signedWitnessRequest(t *testing.T, s *CoreServer, to *witness.Service, aid string, covers bool) witness.WitnessRequest {
	t.Helper()
	seed, err := s.identitySigningSeed()
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	sig, _ := login.SignString(witness.RequestStatement(aid, to.Identity(), covers, stamp), seed)
	return witness.WitnessRequest{RequesterAID: aid, BackendType: witness.BackendDesktop, CoversDelegates: covers, Stamp: stamp, Signature: sig}
}

// Witnesses enrolled before delegates were asked about are asked, by the
// signed agreement request, once the record identity is made; one whose
// operator will not witness delegates is reported.
func TestEnrolledWitnessesAreAskedToCoverTheRecord(t *testing.T) {
	willing, unwilling := startPeer(t, "willing"), startPeer(t, "unwilling")
	unwilling.svc.Store.SetConfig(witness.ConfigDelegates, "off")
	s, _ := foundedWith(t, agentWithDerivedIdentity(t), []string{willing.witnessKey, unwilling.witnessKey}, 1)
	s.DeclaredEntityType = "organization"
	s.logForTest(t, s.DataDir)
	s.vaultForTest(s.DataDir)
	s.ActivityLog.SetEventSigner(&invocationSigner{s: s})
	sq := s.DataStore.(*store.SQLiteStore)
	s.WitnessService = witness.NewService(witness.NewSQLiteStore(sq.DB()), sq, s.KeriDriver, witness.BackendDesktop)
	s.WitnessService.AskToCoverDelegates = s.anchorsItsRecord
	s.WitnessService.SignAsRequester = func(statement string) (string, error) {
		seed, err := s.identitySigningSeed()
		if err != nil {
			return "", err
		}
		return login.SignString(statement, seed)
	}
	owner, _ := s.DataStore.GetIdentity()
	s.WitnessService.OurAID = func() string { return owner.AID }
	for i, p := range []*peerAgent{willing, unwilling} {
		aid := fmt.Sprintf("EPeer%d00000000000000000000000000000000000000", i)
		// The witness answers as the identity it is known by.
		p.svc.OurAID = func() string { return aid }
		s.DataStore.SaveContact(store.ContactRecord{AID: aid, OobiURL: p.base, Status: "accepted", ContactCategory: "trusted"})
		s.WitnessService.Store.SaveContactMeta(witness.ContactMeta{ContactAID: aid, WitnessKey: p.witnessKey})
		// Enrolled already, without delegates.
		p.svc.Contacts.SaveContact(store.ContactRecord{AID: owner.AID, Status: "accepted", ContactCategory: "trusted", PublicKey: owner.PublicKey})
		if res := p.svc.ProcessInboundRequest(context.Background(), signedWitnessRequest(t, s, p.svc, owner.AID, false)); !res.Accepted {
			t.Fatalf("enrolling: %s", res.Reason)
		}
	}
	writeRows(t, s, 2)
	if ok, err := s.anchorRecord(); err != nil || !ok {
		t.Fatalf("anchoring: %v %v", ok, err)
	}
	for i := 0; i < 200 && (!willing.svc.CoversDelegatesOf(owner.AID) || len(s.witnessesDeclining()) == 0); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if !willing.svc.CoversDelegatesOf(owner.AID) {
		t.Fatal("an enrolled witness was not asked to cover the record identity")
	}
	declining := s.witnessesDeclining()
	if _, ok := declining[unwilling.witnessKey]; !ok || len(declining) != 1 {
		t.Fatalf("the witnesses reported declining: %v", declining)
	}
	if got := chainSays(t, s); got["witnesses_declining_record"] == nil {
		t.Fatalf("the check does not report the declining witness: %v", got)
	}

	// Its operator allows delegates later. After a restart, the next
	// anchoring asks again, and it agrees.
	unwilling.svc.Store.SetConfig(witness.ConfigDelegates, "")
	// As enrolled before delegates were asked about: agreed, not covering.
	unwilling.svc.ProcessInboundRequest(context.Background(), signedWitnessRequest(t, s, unwilling.svc, owner.AID, false))
	if unwilling.svc.CoversDelegatesOf(owner.AID) {
		t.Fatal("the coverage was not cleared")
	}
	s.record.coverAsked.Store(false)
	writeRows(t, s, 1)
	if ok, err := s.anchorRecord(); err != nil || !ok {
		t.Fatalf("anchoring again: %v %v", ok, err)
	}
	for i := 0; i < 200 && !unwilling.svc.CoversDelegatesOf(owner.AID); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if !unwilling.svc.CoversDelegatesOf(owner.AID) {
		t.Fatal("the next anchoring after a restart did not ask again")
	}
}

// An Identity Agent that anchors no record still sends its own key log to its
// witnesses: after it issues something, and on the tick, so no witness is left
// with a gap.
func TestEveryIdentityAgentKeepsItsWitnessesUpToDate(t *testing.T) {
	for _, via := range []string{"issuing", "the tick"} {
		t.Run(via, func(t *testing.T) {
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			name := iacrypto.NonTransferableAIDQB64(pub)
			s, _ := foundedWith(t, agentWithDerivedIdentity(t), []string{name}, 1)
			s.DeclaredEntityType = "individual"
			if s.anchorsItsRecord() {
				t.Fatal("this Identity Agent anchors its record")
			}
			sq := s.DataStore.(*store.SQLiteStore)
			s.WitnessService = witness.NewService(witness.NewSQLiteStore(sq.DB()), sq, s.KeriDriver, witness.BackendDesktop)
			s.DataStore.SaveContact(store.ContactRecord{AID: "EWitness0", OobiURL: "http://w0.test", Status: "accepted"})
			s.WitnessService.Store.SaveContactMeta(witness.ContactMeta{ContactAID: "EWitness0", WitnessKey: name})
			s.WitnessService.FetchTip = func(_ context.Context, url string) (witness.TipAnswer, error) {
				return witnessTip(url, nil, priv, name), nil
			}
			owner, _ := s.DataStore.GetIdentity()
			var mu sync.Mutex
			sent := 0
			s.WitnessService.PostEvent = func(_ context.Context, _ string, body []byte) (map[string]interface{}, error) {
				var req struct {
					AID string `json:"aid"`
				}
				json.Unmarshal(body, &req)
				mu.Lock()
				if req.AID == owner.AID {
					sent++
				}
				mu.Unlock()
				return nil, fmt.Errorf("offline")
			}
			if via == "issuing" {
				if _, err := s.grantController(aGrant(GradeEnrolled), time.Now().UTC(), coretypes.Authority{}); err != nil {
					t.Fatal(err)
				}
			} else {
				was := anchorInterval
				anchorInterval = 20 * time.Millisecond
				t.Cleanup(func() { anchorInterval = was })
				stop := make(chan struct{})
				go s.keepAnchoring(stop)
				defer close(stop)
			}
			for i := 0; i < 200; i++ {
				mu.Lock()
				n := sent
				mu.Unlock()
				if n > 0 {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatalf("its own key log did not reach its witnesses by %s", via)
		})
	}
}
