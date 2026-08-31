package recovery

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"identity-agent-core/authprovider"
)

type saying struct {
	level authprovider.Level
	score int
}

func (saying) Name() string { return "test" }
func (s saying) Authenticate() (authprovider.Result, error) {
	return authprovider.Result{
		Level: s.level, Score: s.score, Measured: true, At: time.Now(),
	}, nil
}

// Completing a recovery used to ask one question: does this person control the
// identity. The phrase answers that, and it is not the same as being the person
// the identity belongs to — so the words alone finished a recovery and wrote
// the identity straight in.

func waitedOut(t *testing.T, svc *Service, sess *Session) {
	t.Helper()
	svc.CancelGate.Now = func() time.Time { return time.Now().Add(96 * time.Hour) }
	svc.Rotation.MarkCompleted(sess.ID, RotationResult{})
}

func TestControllingTheIdentityIsNotEnoughToCompleteARecovery(t *testing.T) {
	dir := t.TempDir()
	svc, sess := startedSession(t, dir)
	waitedOut(t, svc, sess)

	// The agent requires somebody verified, and the person here is not.
	svc.RequiredLevel = authprovider.LevelVerified
	svc.Authenticator = saying{level: authprovider.LevelBasic, score: 30}

	_, err := svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic})
	if err == nil {
		t.Fatal("the right phrase completed a recovery for somebody who could not be established as the owner")
	}
	var notAuth *ErrNotAuthenticated
	if !asErr(err, &notAuth) {
		t.Fatalf("refused for the wrong reason: %v", err)
	}

	// And the session survives, so somebody who authenticates properly can
	// still finish. Burning it would mean a failed check restarts the wait.
	if _, gerr := svc.GetSession(sess.ID); gerr != nil {
		t.Fatalf("a failed authentication destroyed the recovery: %v", gerr)
	}

	// Authenticate well enough, and it completes.
	svc.Authenticator = saying{level: authprovider.LevelVerified, score: 95}
	if _, err := svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic}); err != nil {
		t.Fatalf("a verified owner could not complete their own recovery: %v", err)
	}
}

func TestAnAgentThatCannotMeasureDoesNotPretendToPass(t *testing.T) {
	// An agent with no provider must not satisfy a requirement. If it did, the
	// absence of a check would be safer than the check — and removing the
	// provider would be a way past the gate.
	dir := t.TempDir()
	svc, sess := startedSession(t, dir)
	waitedOut(t, svc, sess)

	svc.RequiredLevel = authprovider.LevelBasic
	svc.Authenticator = authprovider.NotConfigured{}

	_, err := svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic})
	if err == nil {
		t.Fatal("an agent that cannot establish anything completed a recovery anyway")
	}
	if !strings.Contains(err.Error(), "nothing here can establish who you are") {
		t.Fatalf("refused without saying what is missing: %v", err)
	}
}

func TestAnAgentWithNoProviderStillRecoversWhenNothingIsRequired(t *testing.T) {
	// The other direction, and it matters as much. Every agent today has no
	// provider, so requiring one by default would lock everybody out of their
	// own identities to protect them from nobody. The waiting period stands in
	// until there is something to ask — and an unmeasured level already draws
	// the longest one.
	dir := t.TempDir()
	svc, sess := startedSession(t, dir)
	waitedOut(t, svc, sess)

	if svc.RequiredLevel != authprovider.LevelUnknown {
		t.Fatalf("a fresh agent enforces %q, which no agent can currently satisfy", svc.RequiredLevel)
	}
	if _, err := svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic}); err != nil {
		t.Fatalf("an ordinary recovery was blocked by a gate nothing can answer: %v", err)
	}
}

func TestTheWaitStillComesFromTheSameProvider(t *testing.T) {
	// One question asked once. The level decides how long the recovery waits,
	// and an agent that measured nothing waits the longest.
	unmeasured := FromAuthProvider{Provider: authprovider.NotConfigured{}}
	band, score, err := unmeasured.CurrentBand()
	if err == nil {
		t.Fatal("no provider was reported as a successful measurement")
	}
	if band != BandUnknown || score != 0 {
		t.Fatalf("an unmeasured agent reported band %q score %d", band, score)
	}

	green := FromAuthProvider{Provider: saying{level: authprovider.LevelHigh, score: 99}}
	if band, score, err := green.CurrentBand(); err != nil || band != BandGreen || score != 99 {
		t.Fatalf("a highly authenticated person got band %q score %d err %v", band, score, err)
	}
	if CancelWindowForBand(BandUnknown) <= CancelWindowForBand(BandGreen) {
		t.Fatal("not knowing who is here waits no longer than knowing exactly")
	}
}

func asErr(err error, target **ErrNotAuthenticated) bool {
	e, ok := err.(*ErrNotAuthenticated)
	if ok {
		*target = e
	}
	return ok
}

type unmeasuredButConfident struct{}

func (unmeasuredButConfident) Name() string { return "confident" }
func (unmeasuredButConfident) Authenticate() (authprovider.Result, error) {
	// A high level, no error, and nothing actually measured. The shape of a bug
	// in somebody else's implementation, and it satisfied the gate.
	return authprovider.Result{Level: authprovider.LevelHigh, Score: 99, Measured: false}, nil
}

func TestClaimingWithoutMeasuringDoesNotSatisfyTheGate(t *testing.T) {
	dir := t.TempDir()
	svc, sess := startedSession(t, dir)
	waitedOut(t, svc, sess)
	svc.RequiredLevel = authprovider.LevelVerified
	svc.Authenticator = unmeasuredButConfident{}

	if _, err := svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic}); err == nil {
		t.Fatal("a provider that measured nothing but claimed a high level satisfied the gate")
	}
}

func TestARequirementThisAgentCannotReadRefusesRatherThanPasses(t *testing.T) {
	// A typo in the requirement used to disable the gate. Unrecognised levels
	// rank alongside unknown, so "verifed" was satisfied by having measured
	// nothing — the misconfiguration made the agent LESS strict, silently.
	dir := t.TempDir()
	svc, sess := startedSession(t, dir)
	waitedOut(t, svc, sess)
	svc.RequiredLevel = authprovider.Level("verifed")
	svc.Authenticator = authprovider.NotConfigured{}

	_, err := svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic})
	if err == nil {
		t.Fatal("a misspelled requirement let an unmeasured operator complete a recovery")
	}
	if !strings.Contains(err.Error(), "does not recognise") {
		t.Fatalf("refused without naming the misconfiguration: %v", err)
	}
}

func TestActivateActuallyConsultsBothGates(t *testing.T) {
	// The gates were tested in isolation and nothing tested that Activate calls
	// them. Deleting either check from Activate left every test passing, which
	// is the defect this repo has shipped before.
	dir := t.TempDir()

	// Gate 2: a requirement that is not met must stop this.
	svc, sess := startedSession(t, dir)
	waitedOut(t, svc, sess)
	svc.RequiredLevel = authprovider.LevelHigh
	svc.Authenticator = saying{level: authprovider.LevelBasic, score: 10}
	if _, err := svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic}); err == nil {
		t.Fatal("Activate does not consult the authentication gate")
	}

	// Gate 3: a hold carried by the archive must stop this, on a device that
	// has no local policy of its own — which is every recovering device.
	dir2 := t.TempDir()
	svc2, sess2 := startedSessionHeldForDuress(t, dir2)
	waitedOut(t, svc2, sess2)
	if _, err := svc2.Activate(sess2.ID, ActivateRequest{Mnemonic: testMnemonic}); err == nil {
		t.Fatal("Activate does not consult the duress gate")
	} else if _, ok := err.(*ErrHeldForDuress); !ok {
		t.Fatalf("stopped for the wrong reason: %v", err)
	}
}

// startedSessionHeldForDuress starts a recovery from an archive whose identity
// chose a waiting period, on a device that has no local policy — which is every
// device a recovery actually runs on.
func startedSessionHeldForDuress(t *testing.T, dir string) (*Service, *Session) {
	t.Helper()
	body, err := json.Marshal(DuressPolicy{Protection: DuressWait, WaitHours: 72})
	if err != nil {
		t.Fatal(err)
	}
	archive := buildTestArchiveWith(t, testMnemonic, nil,
		map[string][]byte{"file:duress_policy.json": body})

	svc := NewService(dir, nil, nil)
	sess, err := svc.Start(StartRequest{
		ArchiveB64: base64.StdEncoding.EncodeToString(archive),
		Mnemonic:   testMnemonic,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The recovering device has no policy of its own, which is the point.
	if svc.LoadDuressPolicy().Protection != DuressNone {
		t.Fatal("this device already has a duress policy, so the test proves nothing")
	}
	return svc, sess
}

type staleButHigh struct{}

func (staleButHigh) Name() string { return "stale" }
func (staleButHigh) Authenticate() (authprovider.Result, error) {
	// Measured, high, and from last week. A provider that caches, or one asked
	// once when the recovery began.
	return authprovider.Result{
		Level: authprovider.LevelHigh, Score: 99, Measured: true,
		At: time.Now().Add(-7 * 24 * time.Hour),
	}, nil
}

func TestAnAuthenticationFromLastWeekDoesNotFinishThisRecovery(t *testing.T) {
	// A recovery waits days, and the gate is checked at the end precisely
	// because who started it says nothing about who is finishing it. A
	// provider answering with a level it established last week defeats that.
	//
	// Result.Fresh existed and was tested and nothing consulted it, which made
	// it look load-bearing when it was not.
	dir := t.TempDir()
	svc, sess := startedSession(t, dir)
	waitedOut(t, svc, sess)
	svc.RequiredLevel = authprovider.LevelVerified
	svc.Authenticator = staleButHigh{}

	if _, err := svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic}); err == nil {
		t.Fatal("a week-old authentication completed a recovery")
	}

	// A current one of the same level does finish it.
	svc.Authenticator = saying{level: authprovider.LevelVerified, score: 90}
	if _, err := svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic}); err != nil {
		t.Fatalf("a current authentication was refused: %v", err)
	}
}

func TestAFailedRecoveryStopsHoldingTheArchive(t *testing.T) {
	// The record stays so somebody can read what went wrong; the sealed
	// identity does not need to stay with it for the thirty days an abandoned
	// session gets.
	dir := t.TempDir()
	svc, sess := startedSession(t, dir)

	svc.ForgetFailed(sess.ID)

	svc.mu.Lock()
	rec, ok := svc.sessions[sess.ID]
	held := ok && len(rec.Archive) > 0
	svc.mu.Unlock()
	if held {
		t.Fatal("a failed recovery is still holding the archive in memory")
	}

	// And it is gone from disk too, while the session itself survives.
	restarted := NewService(dir, nil, nil)
	if _, err := restarted.LoadSessions(); err != nil {
		t.Fatal(err)
	}
	got, err := restarted.GetSession(sess.ID)
	if err != nil {
		t.Fatalf("the record did not survive, so nobody can be told what happened: %v", err)
	}
	if got.ID != sess.ID {
		t.Fatalf("wrong session came back: %+v", got)
	}
	restarted.mu.Lock()
	stillHeld := len(restarted.sessions[sess.ID].Archive) > 0
	restarted.mu.Unlock()
	if stillHeld {
		t.Fatal("the archive came back from disk after the recovery failed")
	}
}
