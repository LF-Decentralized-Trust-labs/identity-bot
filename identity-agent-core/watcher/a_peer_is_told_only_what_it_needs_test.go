package watcher

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"identity-agent-core/store"
)

func storedService(t *testing.T) *Service {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.ApplyIdentityMigrations(db); err != nil {
		t.Fatal(err)
	}
	applyWatcherTables(t, db)
	return NewService(NewSQLiteStore(db))
}

// A peer that records what it is asked.
func recordingPeer(t *testing.T, asked *int32, got *KelCheckRequest) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(asked, 1)
		_ = json.NewDecoder(r.Body).Decode(got)
		_ = json.NewEncoder(w).Encode(KelCheckResponse{})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func contactService(t *testing.T, contactURL string) *Service {
	s := storedService(t)
	s.SignRequest = func(string, string) (string, string, error) { return "Ewatcher", "sig", nil }
	s.L3.AllowLocal = func(string) bool { return true }
	s.PeerWatchers = func() []PeerWatcher { return []PeerWatcher{{AID: "EContact", URL: contactURL}} }
	if err := s.SetPeerWatchEnabled(true); err != nil {
		t.Fatal(err)
	}
	return s
}

// Failed before: every contact was asked about every identity.
func TestAContactIsNotAskedAboutAnIdentityItCannotKnow(t *testing.T) {
	var asked int32
	var got KelCheckRequest
	p := recordingPeer(t, &asked, &got)
	s := contactService(t, p.URL)

	_, _ = s.crossCheckPeers(context.Background(), "EStranger", 0, "Ed", "https://elsewhere.example/oobi/x")
	if asked != 0 {
		t.Fatal("a contact that did not introduce this identity was asked about it")
	}
	// The contact where the log came from is a plausible knower.
	_, _ = s.crossCheckPeers(context.Background(), "EStranger", 0, "Ed", p.URL+"/public/oobi/EStranger")
	if asked != 1 {
		t.Fatalf("the contact that introduced the identity was not asked (%d)", asked)
	}
	// ...and so is one recorded earlier as the source of a first sighting.
	if err := s.RecordFirstSeen("EOther", 0, "Ed", SourceOOBI, p.URL+"/public/oobi/EOther"); err != nil {
		t.Fatal(err)
	}
	_, _ = s.crossCheckPeers(context.Background(), "EOther", 0, "Ed", "")
	if asked != 2 {
		t.Fatalf("a contact recorded as the source was not asked (%d)", asked)
	}
}

// Failed before: the request carried no signature.
func TestAPeerIsAskedWithASignedRequestBoundToIt(t *testing.T) {
	var asked int32
	var got KelCheckRequest
	p := recordingPeer(t, &asked, &got)
	s := contactService(t, p.URL)
	var statement string
	var askedPeer string
	s.SignRequest = func(peerAID, st string) (string, string, error) {
		askedPeer, statement = peerAID, st
		return "Ewatcher", "sig", nil
	}

	_, _ = s.crossCheckPeers(context.Background(), "EAlice", 3, "Ed", p.URL+"/x")
	if got.Requester != "Ewatcher" || got.Signature != "sig" || got.At == 0 {
		t.Fatalf("request was not signed: %+v", got)
	}
	if askedPeer != "EContact" {
		t.Fatalf("signed for %q, not for the contact asked", askedPeer)
	}
	if want := KelCheckRequestStatement("EAlice", 3, "Ed", p.URL, got.At); statement != want || !strings.Contains(statement, "to="+p.URL) {
		t.Fatalf("signed text %q does not name the peer and moment", statement)
	}
}

// No signer means nothing is sent.
func TestNothingIsSentWhenTheRequestCannotBeSigned(t *testing.T) {
	var asked int32
	var got KelCheckRequest
	p := recordingPeer(t, &asked, &got)
	s := contactService(t, p.URL)
	s.SignRequest = nil
	outcomes, _ := s.crossCheckPeers(context.Background(), "EAlice", 0, "Ed", p.URL+"/x")
	if asked != 0 || len(outcomes) != 1 || outcomes[0].Outcome != "unavailable" {
		t.Fatalf("asked=%d outcomes=%+v", asked, outcomes)
	}
}

// Peer checks are off until the owner turns them on: asking tells a contact
// whom this agent deals with.
func TestPeerChecksAreOffUntilTheOwnerTurnsThemOn(t *testing.T) {
	var asked int32
	var got KelCheckRequest
	p := recordingPeer(t, &asked, &got)
	s := contactService(t, p.URL)
	// contactService turns them on; go back to nothing stored.
	if err := s.Store.SetConfig(configPeerWatchEnabled, ""); err != nil {
		t.Fatal(err)
	}
	if s.PeerWatchEnabled() {
		t.Fatal("peer checks should be off by default")
	}
	_, _ = s.crossCheckPeers(context.Background(), "EAlice", 0, "Ed", p.URL+"/x")
	if asked != 0 {
		t.Fatal("a peer was asked before the owner turned peer checks on")
	}
	if err := s.SetPeerWatchEnabled(true); err != nil {
		t.Fatal(err)
	}
	_, _ = s.crossCheckPeers(context.Background(), "EAlice", 0, "Ed", p.URL+"/x")
	if asked != 1 {
		t.Fatalf("asked = %d after the owner turned peer checks on", asked)
	}
}

func TestNoMoreThanAHandfulOfPeersCanBeChosen(t *testing.T) {
	s := storedService(t)
	var many []string
	for i := 0; i <= MaxChosenPeers; i++ {
		many = append(many, "E"+string(rune('a'+i)))
	}
	if err := s.SetChosenPeers(many); err == nil {
		t.Fatal("more than the limit was accepted")
	}
	if err := s.SetChosenPeers(many[:MaxChosenPeers]); err != nil {
		t.Fatal(err)
	}
	if got := s.ChosenPeers(); len(got) != MaxChosenPeers {
		t.Fatalf("chosen = %v", got)
	}
	// A longer list stored some other way is still cut to the limit.
	b, _ := json.Marshal(append(many, "Eextra"))
	_ = s.Store.SetConfig(configPeerWatchAIDs, string(b))
	if got := s.ChosenPeers(); len(got) != MaxChosenPeers {
		t.Fatalf("chosen = %v", got)
	}
}

func TestSettingsAreRefusedNotLostWhenThereIsNoStore(t *testing.T) {
	s := &Service{}
	if err := s.SetChosenPeers([]string{"EOne"}); err == nil {
		t.Fatal("peers were reported chosen with nowhere to keep them")
	}
	if err := s.SetPeerWatchEnabled(false); err == nil {
		t.Fatal("peer checks were reported off with nowhere to keep that")
	}
}

// A contact is never asked about itself: the identity cannot corroborate its
// own log, even where the log was first seen at that contact's address.
func TestAContactIsNotAskedAboutItself(t *testing.T) {
	var asked int32
	var got KelCheckRequest
	p := recordingPeer(t, &asked, &got)
	s := contactService(t, p.URL)
	_, _ = s.crossCheckPeers(context.Background(), "EContact", 0, "Ed", p.URL+"/public/oobi/EContact")
	if asked != 0 {
		t.Fatal("a contact was asked to corroborate its own key log")
	}
}

// Only an address under the contact's base counts as where the contact is, not
// one that begins with the same letters.
func TestSameBaseIsStrictAboutWhereAnAddressLies(t *testing.T) {
	for _, c := range []struct {
		base, u string
		want    bool
	}{
		{"https://a.example", "https://a.example", true},
		{"https://a.example/", "https://a.example/public/oobi/x", true},
		{"https://a.example", "https://a.example.evil.example/x", false},
		{"https://a.example", "https://a.examples/x", false},
		{"https://a.example/base", "https://a.example/basement", false},
		{"", "https://a.example", false},
		{"https://a.example", "", false},
	} {
		if got := sameBase(c.base, c.u); got != c.want {
			t.Errorf("sameBase(%q, %q) = %v, want %v", c.base, c.u, got, c.want)
		}
	}
}
