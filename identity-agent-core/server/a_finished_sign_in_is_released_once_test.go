package server

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/login"
)

func aSettledSignIn(t *testing.T, w *aWebsiteWorld) BrowserKeySignIn {
	t.Helper()
	in, err := w.org.startBrowserKeySignIn("the-website", "https://portal.example", aBrowserKey, w.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aPersonsIdentityAgent(t).Approve(login.StartLoginRequest{SessionToken: in.Session, RPSessionURL: w.srv.URL}); err != nil {
		t.Fatal(err)
	}
	return in
}

// The collector secret releases a finished sign-in once. A second read, by the
// same holder, gets that it ended and nothing about the person.
func TestAFinishedSignInIsReleasedOnceAndThenForgotten(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	in := aSettledSignIn(t, w)

	res, err := w.org.browserKeySignInResult(in.Session, in.Collector)
	if err != nil || res.State != "verified" || res.Pairwise == "" {
		t.Fatalf("the first read: %+v %v", res, err)
	}
	if _, err := w.org.browserKeySignInResult(in.Session, in.Collector); err == nil {
		t.Fatal("a sign-in already collected was released a second time")
	}
	st, _, _, _ := w.org.collectSignIn(in.Session, in.Collector, time.Now())
	for _, k := range []string{"pairwise_aid", "disclosures", "browser_key", "member_info"} {
		if _, kept := st[k]; kept {
			t.Fatalf("%s is still held after the result was collected", k)
		}
	}
	// And the forgetting survives a restart.
	after := &CoreServer{DataDir: w.org.DataDir}
	if err := after.loadChallengeState(w.org.DataDir); err != nil {
		t.Fatal(err)
	}
	if st := after.challengeStatusOf(in.Session); st["pairwise_aid"] != nil || st["status"] != "complete" {
		t.Fatalf("after a restart: %v", st)
	}
}

// Past the window, even the first read by the holder of the secret gets nothing.
func TestAFinishedSignInIsNotReleasedAfterItsWindow(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	in := aSettledSignIn(t, w)

	late := time.Now().Add(signInResultWindow + time.Minute)
	st, bound, held, err := w.org.collectSignIn(in.Session, in.Collector, late)
	if err != nil || !bound || !held {
		t.Fatalf("bound=%v held=%v err=%v", bound, held, err)
	}
	if st["pairwise_aid"] != nil || st["released"] != true {
		t.Fatalf("a result past its window was released: %v", st)
	}
	// Reading it on time afterwards does not bring it back.
	if _, err := w.org.browserKeySignInResult(in.Session, in.Collector); err == nil {
		t.Fatal("a result forgotten past its window was released later")
	}
}

// Somebody without the secret takes nothing: the person's result is still
// there for the holder afterwards.
func TestReadingWithoutTheSecretDoesNotSpendTheResult(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	in := aSettledSignIn(t, w)
	if _, _, held, _ := w.org.collectSignIn(in.Session, "not-the-secret", time.Now()); held {
		t.Fatal("a wrong secret was accepted")
	}
	if res, err := w.org.browserKeySignInResult(in.Session, in.Collector); err != nil || res.Pairwise == "" {
		t.Fatalf("the holder lost the result to a stranger's read: %+v %v", res, err)
	}
}

// An agent that cannot record a sign-in does not start it, and does not keep
// it in memory only.
func TestASignInTheAgentCannotRecordIsNotStarted(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	// A directory where the state file goes: the write cannot succeed.
	if err := os.Mkdir(filepath.Join(w.org.DataDir, challengeStateFile), 0o700); err != nil {
		t.Fatal(err)
	}
	before := len(w.org.challenges)
	token, _, code, _ := w.org.createSignedAssetChallenge("the-website", "https://portal.example", "", nil, aBrowserKey, "", w.srv.URL)
	if code != http.StatusInternalServerError || token != "" {
		t.Fatalf("a sign-in that could not be recorded was started: token=%q code=%d", token, code)
	}
	if len(w.org.challenges) != before || len(w.org.challengeStatus) != 0 {
		t.Fatalf("the refused sign-in is held in memory: %d challenges, %d statuses", len(w.org.challenges), len(w.org.challengeStatus))
	}
	if _, err := w.org.startBrowserKeySignIn("the-website", "https://portal.example", aBrowserKey, w.srv.URL); err == nil {
		t.Fatal("an add-on was given a sign-in the agent could not record")
	}
	if _, err := w.org.mintCollectorSecret("x"); err == nil || len(w.org.challengeCollector) != 0 {
		t.Fatalf("a collector secret was minted that could not be recorded: %v", err)
	}
}

// breakTheStateFile puts a directory where the state file goes, so every write
// fails, and returns a function that puts things right.
func breakTheStateFile(t *testing.T, dir string) (mend func()) {
	t.Helper()
	path := filepath.Join(dir, challengeStateFile)
	saved, rerr := os.ReadFile(path)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if rerr == nil {
			if err := os.WriteFile(path, saved, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// If the answer cannot be recorded the sign-in stays pending, in memory and so
// in the file, and the caller is told: otherwise a restart would accept the
// same assertion again inside its window.
func TestAnAnswerTheAgentCannotRecordSettlesNothing(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	in, err := w.org.startBrowserKeySignIn("the-website", "https://portal.example", aBrowserKey, w.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	mend := breakTheStateFile(t, w.org.DataDir)
	if err := w.org.setChallengeStatus(in.Session, map[string]interface{}{"status": "denied"}); err == nil {
		t.Fatal("a status that could not be written was reported as written")
	}
	if _, err := aPersonsIdentityAgent(t).Approve(login.StartLoginRequest{SessionToken: in.Session, RPSessionURL: w.srv.URL}); err == nil {
		t.Fatal("an answer the agent could not record was accepted (want 500)")
	}
	if st := w.org.challengeStatusOf(in.Session); st["status"] != "pending" {
		t.Fatalf("the sign-in settled in memory though the file still says pending: %v", st)
	}
	mend()
	after := &CoreServer{DataDir: w.org.DataDir}
	if err := after.loadChallengeState(w.org.DataDir); err != nil {
		t.Fatal(err)
	}
	if st := after.challengeStatusOf(in.Session); st["status"] != "pending" {
		t.Fatalf("after a restart: %v", st)
	}
}

// When the forgetting cannot be recorded the result is not released, and it is
// still there for the holder to collect once the agent can write again. Without
// the rollback it would be forgotten in memory, never released, and lost.
func TestAFailedForgettingReleasesNothingAndLosesNothing(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	in := aSettledSignIn(t, w)

	mend := breakTheStateFile(t, w.org.DataDir)
	st, _, held, err := w.org.collectSignIn(in.Session, in.Collector, time.Now())
	if err == nil || !held || st != nil {
		t.Fatalf("a result was released though the forgetting was not recorded: st=%v held=%v err=%v", st, held, err)
	}
	if cur := w.org.challengeStatusOf(in.Session); cur["released"] == true || cur["pairwise_aid"] == nil {
		t.Fatalf("the status was left forgotten in memory after the save failed: %v", cur)
	}
	mend()
	if res, err := w.org.browserKeySignInResult(in.Session, in.Collector); err != nil || res.Pairwise == "" {
		t.Fatalf("the holder could not collect after the agent could write again: %+v %v", res, err)
	}
}

// A result nobody collects is forgotten once its window has passed, in memory
// and in the file, without anyone asking for it. One inside its window, and
// one still pending, are left alone.
func TestAnUncollectedResultIsForgottenAfterItsWindow(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	old := aSettledSignIn(t, w)
	pending, err := w.org.startBrowserKeySignIn("the-website", "https://portal.example", aBrowserKey, w.srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	if n, err := w.org.forgetUncollectedResults(time.Now()); err != nil || n != 0 {
		t.Fatalf("a result inside its window was forgotten: n=%d err=%v", n, err)
	}
	late := time.Now().Add(signInResultWindow + time.Minute)

	// A failed save changes nothing.
	mend := breakTheStateFile(t, w.org.DataDir)
	if n, err := w.org.forgetUncollectedResults(late); err == nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if w.org.challengeStatusOf(old.Session)["pairwise_aid"] == nil {
		t.Fatal("the result was dropped from memory though the file could not be updated")
	}
	mend()

	if n, err := w.org.forgetUncollectedResults(late); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	after := &CoreServer{DataDir: w.org.DataDir}
	if err := after.loadChallengeState(w.org.DataDir); err != nil {
		t.Fatal(err)
	}
	for name, srv := range map[string]*CoreServer{"memory": w.org, "file": after} {
		st := srv.challengeStatusOf(old.Session)
		for _, k := range []string{"pairwise_aid", "disclosures", "browser_key", "member_info"} {
			if _, kept := st[k]; kept {
				t.Fatalf("%s still holds %s of a result nobody collected", name, k)
			}
		}
		if st["status"] != "complete" || st["released"] != true {
			t.Fatalf("%s: %v", name, st)
		}
		if srv.challengeStatusOf(pending.Session)["status"] != "pending" {
			t.Fatalf("%s: a pending sign-in was disturbed", name)
		}
	}
	if _, err := w.org.browserKeySignInResult(old.Session, old.Collector); err == nil {
		t.Fatal("a result forgotten unread was released later")
	}
}
