package server

import (
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/login"
)

// A sign-in answered before a restart is still answered after it, the
// challenge is still there for a person partway through, and the secret that
// collects the result still collects it.
func TestRestartKeepsTheSignInChallenges(t *testing.T) {
	dir := t.TempDir()
	before := &CoreServer{DataDir: dir}
	before.challenges = map[string]login.ChallengeBundle{
		"answered": {Nonce: "n1", Audience: "a", SiteAID: "site"},
		"waiting":  {Nonce: "n2", Audience: "a", SiteAID: "site"},
	}
	before.challengeStatus = map[string]map[string]interface{}{"waiting": {"status": "pending"}}
	before.setChallengeStatus("answered", map[string]interface{}{"status": "complete", "pairwise_aid": "EP"})
	secret, err := before.mintCollectorSecret("answered")
	if err != nil {
		t.Fatal(err)
	}

	after := &CoreServer{DataDir: dir}
	if err := after.loadChallengeState(dir); err != nil {
		t.Fatal(err)
	}
	if after.challenges["answered"].Nonce != "n1" || after.challenges["waiting"].Nonce != "n2" {
		t.Fatalf("challenges lost over a restart: %v", after.challenges)
	}
	if st := after.challengeStatusOf("answered"); st["status"] != "complete" || st["pairwise_aid"] != "EP" {
		t.Fatalf("the settled mark was lost over a restart: %v", st)
	}
	if st := after.challengeStatusOf("waiting"); st["status"] != "pending" {
		t.Fatalf("a waiting challenge changed over a restart: %v", st)
	}
	if bound, held := after.collectorHeld("answered", secret); !bound || !held {
		t.Fatalf("the collector secret stopped working over a restart (bound=%v held=%v)", bound, held)
	}
	if _, held := after.collectorHeld("answered", "another"); held {
		t.Fatal("a wrong collector secret was accepted")
	}
}

// A state file that cannot be read stops the agent: starting empty would
// reopen every sign-in already answered.
func TestUnreadableChallengeStateIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, challengeStateFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&CoreServer{}).loadChallengeState(dir); err == nil {
		t.Fatal("an unreadable challenge state was taken for an empty one")
	}
}
