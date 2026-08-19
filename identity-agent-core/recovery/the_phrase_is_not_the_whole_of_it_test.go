package recovery

import (
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
