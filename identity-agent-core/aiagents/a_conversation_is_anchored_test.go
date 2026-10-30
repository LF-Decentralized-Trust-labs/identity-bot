package aiagents

import (
	"database/sql"
	"identity-agent-core/conversation"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// A conversation's newest entries are anchored with the record.

// A conversation's newest entry is anchored too: changing it afterwards is
// caught.
func TestAConversationsHeadIsAnchored(t *testing.T) {
	w := newTalkWorld(t)
	w.s.ActivityLog.SetEventSigner(fixtures.LogEventSigner(w.s))
	conv, _ := w.openedWith(t)
	if anchored, err := hostOf(w.s).AnchorRecord(); err != nil || !anchored {
		t.Fatalf("anchoring: %v %v", anchored, err)
	}
	if got := fixtures.ChainSays(t, w.s); got["intact"] != true {
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
	if got := fixtures.ChainSays(t, w.s); got["intact"] != false || got["anchor_broken_at"] == nil {
		t.Fatalf("changing an anchored conversation entry went unnoticed: %v", got)
	}
}

// Messages a conversation takes count towards the next anchoring.
func TestAConversationsMessagesBringOnAnAnchoring(t *testing.T) {
	w := newTalkWorld(t)
	w.s.ActivityLog.SetEventSigner(fixtures.LogEventSigner(w.s))
	fixtures.AnchorAfter(t, 1)
	w.openedWith(t)
	for i := 0; i < 100; i++ {
		if anchors, _ := w.s.DataStore.GetRecordAnchors(); len(anchors) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("a message the conversation took did not bring on an anchoring")
}

// A conversation entry is anchored by its sequence: entries added after an
// anchoring are counted unanchored until the next.
func TestConversationEntriesAreAnchoredBySequence(t *testing.T) {
	w := newTalkWorld(t)
	w.s.DeclaredEntityType = "organization"
	w.s.ActivityLog.SetEventSigner(fixtures.LogEventSigner(w.s))
	conv, _ := w.openedWith(t)
	if ok, err := hostOf(w.s).AnchorRecord(); err != nil || !ok {
		t.Fatalf("anchoring: %v %v", ok, err)
	}
	if got := fixtures.ChainSays(t, w.s); got["unanchored_entries"] != float64(0) {
		t.Fatalf("after anchoring: %v", got)
	}
	if code, out := w.personSays(t, w.a, conv, "and another"); code != http.StatusCreated {
		t.Fatalf("second message: %d %v", code, out)
	}
	if got := fixtures.ChainSays(t, w.s); got["unanchored_entries"] != float64(1) {
		t.Fatalf("a new entry is not counted unanchored: %v", got)
	}
	if ok, err := hostOf(w.s).AnchorRecord(); err != nil || !ok {
		t.Fatalf("anchoring again: %v %v", ok, err)
	}
	if got := fixtures.ChainSays(t, w.s); got["unanchored_entries"] != float64(0) || got["intact"] != true {
		t.Fatalf("the new entry was not anchored: %v", got)
	}
}

// A conversation's last entry is anchored before it can close by going quiet.
func TestTheRecordIsAnchoredBeforeAQuietConversationCloses(t *testing.T) {
	fixtures.AnchorAtLeastEvery(t, 2*conversation.IdleClose)
	if helpers.AnchorTick() > conversation.IdleClose/2 {
		t.Fatalf("anchoring every %s would let a conversation close unanchored", helpers.AnchorTick())
	}
}
