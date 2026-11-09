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

// Whoever starts a sign-in can read last_refusal, and a credential can name any
// issuer. So the reason for a refused credential is the same few phrases
// however the check failed, and nothing the check found out reaches the browser:
// not the error text, not whether this agent holds a key log for the issuer.
func TestARefusedCredentialIsReportedInFixedWordsWhateverTheCheckFound(t *testing.T) {
	internal := []string{"verify error", "KEL", "issuer", "subject", "watcher", "duplicity", "driver", "engine", "credential verification failed"}
	allowed := map[string]bool{refusalCredentialMissing: true, refusalCredentialUnchecked: true, refusalCredentialNotAllowed: true}
	cases := map[string]*aGateWorld{
		"issuer log not held":     aGateWorldIssuingTo(t, true, false),
		"issued to somebody else": aGateWorldIssuingTo(t, false, true),
	}
	var got []string
	for name, w := range cases {
		ok, reason := w.gate(t)
		if ok {
			t.Fatalf("%s: admitted", name)
		}
		if !allowed[reason] {
			t.Errorf("%s: the browser was given %q", name, reason)
		}
		for _, bad := range internal {
			if strings.Contains(reason, bad) {
				t.Errorf("%s: %q contains %q", name, reason, bad)
			}
		}
		got = append(got, reason)
	}
	// An issuer this agent holds a log for and one it does not look the same.
	if got[0] != got[1] {
		t.Errorf("the reason tells the two failures apart: %q vs %q", got[0], got[1])
	}
	// Presenting nothing is the presenter's own news and says so.
	s := gateServer(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen, RequiredCredSchema: "SCH"})
	if ok, r := s.authorizeAssetAccess(nil, "ESite", "Ex", nil); ok || r != refusalCredentialMissing {
		t.Errorf("nothing presented: %v %q", ok, r)
	}
}
