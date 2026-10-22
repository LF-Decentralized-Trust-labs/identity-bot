package server

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/keriengine"
	"identity-agent-core/sandbox"

	keri "github.com/grapeid/keri-go"
)

// recordWorld is an organisation that holds its own key, with a signed log.
func recordWorld(t *testing.T) *CoreServer {
	t.Helper()
	s, _ := grantWorld(t)
	m, err := sandbox.NewManager(sandbox.ManagerConfig{DataDir: s.DataDir, ManifestsDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	s.SandboxManager = m
	m.SetEventSigner(&invocationSigner{s: s})
	return s
}

func writeRows(t *testing.T, s *CoreServer, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if s.SandboxManager.RecordGovernanceEvent(sandbox.CallerContext{CallerAID: "EAgent", Reason: "test"}, "test.event", "ok") == 0 {
			t.Fatal("a row was not written")
		}
	}
}

func chainSays(t *testing.T, s *CoreServer) map[string]any {
	t.Helper()
	req := local("GET", "/api/activity/chain", "")
	rec := httptest.NewRecorder()
	s.handleVerifyAuditChain(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("checking the log: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
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
	row, _, _ := s.SandboxManager.Store().Head()
	if got["intact"] != true || got["anchored_through"] != float64(row) || got["unanchored_rows"] != float64(0) {
		t.Fatalf("after anchoring the log reads %v", got)
	}

	writeRows(t, s, 1)
	if got := chainSays(t, s); got["intact"] != true || got["unanchored_rows"] != float64(1) {
		t.Fatalf("a row written after the anchoring is not reported as unanchored: %v", got)
	}

	// Remove the newest rows, the anchored one among them. No row names them,
	// so only the anchor can tell.
	db := s.SandboxManager.Store().DB()
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

// A conversation's newest entry is anchored too: changing it afterwards is
// caught.
func TestAConversationsHeadIsAnchored(t *testing.T) {
	w := newTalkWorld(t)
	w.s.SandboxManager.SetEventSigner(&invocationSigner{s: w.s})
	conv, _ := w.openedWith(t)
	if anchored, err := w.s.anchorRecord(); err != nil || !anchored {
		t.Fatalf("anchoring: %v %v", anchored, err)
	}
	if got := chainSays(t, w.s); got["intact"] != true {
		t.Fatalf("the log does not hold after anchoring a conversation: %v", got)
	}
	db, err := sql.Open("sqlite", filepath.Join(w.s.DataDir, "conversations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE entries SET hash = 'Echanged' WHERE conversation = ?`, conv); err != nil {
		t.Fatal(err)
	}
	if got := chainSays(t, w.s); got["intact"] != false || got["anchor_broken_at"] == nil {
		t.Fatalf("changing an anchored conversation entry went unnoticed: %v", got)
	}
}

// Enough recorded messages anchor the record without waiting for the interval.
func TestEnoughMessagesAnchorTheRecord(t *testing.T) {
	s := recordWorld(t)
	was := anchorEvery
	anchorEvery = 3
	t.Cleanup(func() { anchorEvery = was })
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
	was := anchorInterval
	anchorInterval = 20 * time.Millisecond
	t.Cleanup(func() { anchorInterval = was })
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
	if anchored, err := s.anchorRecord(); err == nil || anchored {
		t.Fatalf("the record was anchored under a key this Identity Agent does not hold: %v", err)
	}
	if after, _ := s.DataStore.GetEvents(owner.AID); len(after) != len(before) {
		t.Fatal("an event was written into a key log whose key is elsewhere")
	}
}

// Messages a conversation takes count towards the next anchoring.
func TestAConversationsMessagesBringOnAnAnchoring(t *testing.T) {
	w := newTalkWorld(t)
	w.s.SandboxManager.SetEventSigner(&invocationSigner{s: w.s})
	was := anchorEvery
	anchorEvery = 1
	t.Cleanup(func() { anchorEvery = was })
	w.openedWith(t)
	for i := 0; i < 100; i++ {
		if anchors, _ := w.s.DataStore.GetRecordAnchors(); len(anchors) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("a message the conversation took did not bring on an anchoring")
}
