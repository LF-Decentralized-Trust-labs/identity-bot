package asset

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Nothing the store writes can be used as a token.
func TestAnIssuedTokenIsNotRecoverableFromTheStore(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	e := issueToken(t, h, "a device", "host", "")
	if e.Token == "" {
		t.Fatal("the issuer was not given the token")
	}
	files, _ := filepath.Glob(filepath.Join(h.Store.dataDir, "*"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), e.Token) {
			t.Errorf("%s holds the token in the clear", f)
		}
	}
	for _, l := range h.Store.ListEnrolments() {
		if l.Token != "" {
			t.Error("listing enrolments returned a token")
		}
	}
	if _, ok := h.Store.GetEnrolment(e.ID); ok {
		t.Error("the stored ID was accepted as if it were the token")
	}
	if _, err := h.Store.ClaimEnrolment(e.ID, time.Now()); err == nil {
		t.Error("the stored ID claimed the enrolment")
	}
}

func TestANewerTokenForTheSameMachineVoidsTheOlder(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	old := issueToken(t, h, "the build box", "host", "")
	other := issueToken(t, h, "another box", "host", "")
	newer := issueToken(t, h, "the build box", "host", "")
	if w := enrol(t, h, old.Token, newTestMachine(t)); w.Code != http.StatusForbidden {
		t.Errorf("the older token still works: %d", w.Code)
	}
	if w := enrol(t, h, other.Token, newTestMachine(t)); w.Code != http.StatusCreated {
		t.Errorf("a token for a different machine was voided: %d", w.Code)
	}
	if w := enrol(t, h, newer.Token, newTestMachine(t)); w.Code != http.StatusCreated {
		t.Errorf("the newer token was refused: %d", w.Code)
	}
}

func TestATokenCannotBeReusedAfterEnrolling(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	e := issueToken(t, h, "a device", "host", "")
	if w := enrol(t, h, e.Token, newTestMachine(t)); w.Code != http.StatusCreated {
		t.Fatalf("first use: %d", w.Code)
	}
	if _, err := h.Store.ClaimEnrolment(e.Token, time.Now()); err == nil {
		t.Error("a spent token was claimed again")
	}
}

func TestARevokedTokenCanBeRevokedByItsListedID(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	e := issueToken(t, h, "a device", "host", "")
	if err := h.Store.RevokeEnrolment(e.ID); err != nil {
		t.Fatal(err)
	}
	if w := enrol(t, h, e.Token, newTestMachine(t)); w.Code != http.StatusForbidden {
		t.Errorf("a revoked token was accepted: %d", w.Code)
	}
}

// A file an earlier version wrote holds the token as its key. Opening the store
// carries a good token across and leaves no plaintext behind.
func TestATokenStoredInTheClearByAnEarlierVersionIsCarriedAcross(t *testing.T) {
	h := newEnrolHandler(t, newFakeKeri(t))
	dir := h.Store.dataDir
	const legacy = "00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff"
	now := time.Now().UTC()
	b, _ := json.Marshal(map[string]Enrolment{legacy: {
		Token: legacy, DisplayName: "old", AssetType: "host",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}})
	if err := os.WriteFile(filepath.Join(dir, "asset_enrolments.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if w := enrol(t, h, legacy, newTestMachine(t)); w.Code != http.StatusCreated {
		t.Fatalf("a still-good token from the old file was refused: %d", w.Code)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "asset_enrolments.json"))
	if strings.Contains(string(raw), legacy) {
		t.Error("the old plaintext token is still in the file")
	}
}
