package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/asset"
)

// A forged post is refused and noted in memory only. If each one rewrote the
// state file, anyone who had seen the QR code could make the agent do it as
// often as they liked.
func TestARefusalDoesNotSaveTheStateFile(t *testing.T) {
	dir := t.TempDir()
	s := &CoreServer{
		DataDir:         dir,
		challengeStatus: map[string]map[string]interface{}{"t": {"status": "pending"}},
	}
	for i := 0; i < 5; i++ {
		s.recordRefusal("t", "not on the roster")
	}
	if _, err := os.Stat(filepath.Join(dir, challengeStateFile)); !os.IsNotExist(err) {
		t.Fatalf("recording a refusal wrote the state file (stat: %v)", err)
	}
	if got := s.challengeStatus["t"]["refusals"]; got != 5 {
		t.Fatalf("the refusals were not counted in memory: %v", got)
	}
}

// The reason for a refusal reaches the browser that started the sign-in, so
// when the asset store cannot be read it is fixed wording, not the error.
func TestAnUnreadableAssetStoreIsRefusedInFixedWords(t *testing.T) {
	dir := damagedStore(t, "assets.json")
	st, err := asset.NewStore(dir)
	if st == nil {
		t.Fatalf("no store over a damaged assets file: %v", err)
	}
	s := &CoreServer{assetHandler: &asset.Handler{Store: st}}
	ok, reason := s.authorizeAssetAccess(context.Background(), "ESite", "EPerson", nil)
	if ok {
		t.Fatal("an unreadable asset store admitted somebody")
	}
	if reason == "" || strings.Contains(reason, dir) || strings.Contains(reason, "assets.json") || strings.Contains(strings.ToLower(reason), "unmarshal") || strings.Contains(reason, "unexpected") {
		t.Fatalf("the reason names the internal error: %q", reason)
	}
}
