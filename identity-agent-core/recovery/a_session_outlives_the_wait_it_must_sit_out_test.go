package recovery

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Recovery imposes a cancel window — a day at minimum, two by default — so
// somebody who did not start the recovery has time to stop it. Sessions lived
// in a map in memory, so any restart lost them: a session could not outlive the
// wait it was required to sit out, and over two days a restart is the expected
// case. The feature could not complete by construction.

func startedSession(t *testing.T, dir string) (*Service, *Session) {
	t.Helper()
	svc := NewService(dir, nil, nil)
	archive := buildTestArchive(t, testMnemonic, nil)
	sess, err := svc.Start(StartRequest{
		ArchiveB64: base64.StdEncoding.EncodeToString(archive),
		Mnemonic:   testMnemonic,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, sess
}

func TestARecoveryOutlivesTheAgentThatStartedIt(t *testing.T) {
	dir := t.TempDir()
	_, sess := startedSession(t, dir)

	// The agent stops and starts. Everything in memory is gone.
	restarted := NewService(dir, nil, nil)
	if _, ok := restarted.sessions[sess.ID]; ok {
		t.Fatal("test is not exercising a restart")
	}

	n, err := restarted.LoadSessions()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected one session to come back, got %d", n)
	}

	got, err := restarted.GetSession(sess.ID)
	if err != nil {
		t.Fatalf("the session did not survive the restart: %v", err)
	}
	if got.IdentityAID != sess.IdentityAID || got.CompleteAfter != sess.CompleteAfter {
		t.Fatalf("the session came back different: %+v vs %+v", got, sess)
	}
	// The wait is not restarted by the restart, which would make it unservable.
	if got.StartedAt != sess.StartedAt {
		t.Fatal("the waiting period started again, so it can never be waited out")
	}
}

func TestTheRecoveryPhraseIsNotWrittenDownWhileWaiting(t *testing.T) {
	// The phrase opens everything, and the wait exists precisely because
	// somebody may not be who they claim. Keeping it on disk for two days to
	// save typing would undo the thing being waited for.
	dir := t.TempDir()
	_, sess := startedSession(t, dir)

	path := filepath.Join(dir, "recovery_sessions", sess.ID+".json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("nothing was written down, so the session cannot survive: %v", err)
	}
	if strings.Contains(string(body), testMnemonic) {
		t.Fatal("the recovery phrase was written to disk")
	}
	// Not just the literal string. Base64 contains no spaces, so looking for
	// " word " would pass against a phrase written as a JSON array or encoded —
	// which are exactly the ways it would end up there by accident.
	words := strings.Fields(testMnemonic)
	for _, form := range []string{
		testMnemonic,
		strings.Join(words, ","),
		strings.Join(words, `","`),
		base64.StdEncoding.EncodeToString([]byte(testMnemonic)),
		base64.URLEncoding.EncodeToString([]byte(testMnemonic)),
	} {
		if strings.Contains(string(body), form) {
			t.Fatal("the recovery phrase was written to disk")
		}
	}
	// And the seed it derives, which is just as good to an attacker.
	seed, serr := BIP39Seed(OpenRequest{Mnemonic: testMnemonic})
	if serr == nil {
		if strings.Contains(string(body), base64.StdEncoding.EncodeToString(seed)) {
			t.Fatal("the seed the phrase derives was written to disk")
		}
	}

	// And the file is not world-readable.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatalf("the session file is readable by others: %v", info.Mode().Perm())
	}
}

func TestFinishingARecoveryNeedsThePhraseAgain(t *testing.T) {
	dir := t.TempDir()
	svc, sess := startedSession(t, dir)

	// Wait it out and satisfy the rotation gate, so the only thing left to
	// test is the phrase.
	svc.CancelGate.Now = func() time.Time { return time.Now().Add(96 * time.Hour) }
	svc.Rotation.MarkCompleted(sess.ID, RotationResult{})

	if _, err := svc.Activate(sess.ID, ActivateRequest{}); err == nil {
		t.Fatal("a recovery completed with no recovery phrase")
	} else if !strings.Contains(err.Error(), "needed again") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}

	if _, err := svc.Activate(sess.ID, ActivateRequest{Mnemonic: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"}); err == nil {
		t.Fatal("a recovery completed with the wrong recovery phrase")
	}

	// A wrong phrase must not burn the session: the wait would start again.
	if _, err := svc.GetSession(sess.ID); err != nil {
		t.Fatalf("a mistyped phrase destroyed the session: %v", err)
	}

	if _, err := svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic}); err != nil {
		t.Fatalf("the right phrase did not finish the recovery: %v", err)
	}

	// The sealed archive is not kept once it has been used.
	if _, err := os.Stat(filepath.Join(dir, "recovery_sessions", sess.ID+".json")); !os.IsNotExist(err) {
		t.Fatal("the archive is still on disk after the recovery finished")
	}
}

func TestASessionIdCannotBeAPath(t *testing.T) {
	for _, bad := range []string{"../../etc/passwd", "..", "", "a/b", strings.Repeat("x", 36)} {
		if err := acceptableSessionID(bad); err == nil {
			t.Fatalf("accepted %q as a session id", bad)
		}
	}
	if err := acceptableSessionID("3f2504e0-4f89-11d3-9a0c-0305e82c3301"); err != nil {
		t.Fatalf("refused a real session id: %v", err)
	}
}

func TestAnAbandonedRecoveryIsNotKeptForever(t *testing.T) {
	// An abandoned recovery must not leave somebody's sealed archive on disk
	// indefinitely. The bound is far longer than the longest window, so no
	// legitimate wait comes near it.
	dir := t.TempDir()
	_, sess := startedSession(t, dir)

	path := filepath.Join(dir, "recovery_sessions", sess.ID+".json")
	body, _ := os.ReadFile(path)
	stale := string(body)
	old := time.Now().Add(-sessionMaxAge - time.Hour).UTC().Format(time.RFC3339)
	// Rewrite written_at to something older than the bound.
	i := strings.Index(stale, `"written_at":"`)
	j := strings.Index(stale[i+14:], `"`) + i + 14
	stale = stale[:i+14] + old + stale[j:]
	if err := os.WriteFile(path, []byte(stale), 0600); err != nil {
		t.Fatal(err)
	}

	restarted := NewService(dir, nil, nil)
	n, err := restarted.LoadSessions()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("an abandoned recovery was resumed")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("an abandoned recovery still has its sealed archive on disk")
	}
}

func TestAnUnmeasuredAssuranceBandIsNotReportedAsAMeasurement(t *testing.T) {
	// The band decides how long somebody who did not start this recovery has to
	// stop it. With no provider reachable — which is every deployment that has
	// not configured one — the gate reported "amber" and a 48-hour window, so a
	// graded assurance level appeared on screen having been measured by
	// nothing. It was also the shorter of the two available answers, so the
	// guess erred towards less protection.
	var g *StubAuthProviderGate
	band, score, err := g.CurrentBand()
	if err == nil {
		t.Fatal("no provider at all was reported as a successful measurement")
	}
	if band != BandUnknown {
		t.Fatalf("an unmeasured band was reported as %q", band)
	}
	if score != 0 {
		t.Fatalf("a score of %d was invented for an agent with no provider", score)
	}

	// Unreachable behaves the same way.
	unreachable := &StubAuthProviderGate{BaseURL: "http://127.0.0.1:1"}
	if band, _, err := unreachable.CurrentBand(); err == nil || band != BandUnknown {
		t.Fatalf("an unreachable provider produced band %q, err %v", band, err)
	}
}

func TestNotKnowingMeansWaitingLongerNotLess(t *testing.T) {
	// The window exists so somebody who did not start this recovery can stop
	// it. When nothing is known about who is asking, the answer that protects
	// the owner is more time. The unknown case used to fall through to the
	// minimum, so an agent that could measure nothing waited the least.
	unknown := CancelWindowForBand(BandUnknown)
	if unknown < CancelWindowForBand(BandRed) {
		t.Fatalf("an unmeasured band waits %v, less than the least trusted band's %v",
			unknown, CancelWindowForBand(BandRed))
	}
	if unknown <= CancelWindowForBand(BandGreen) {
		t.Fatalf("an unmeasured band waits no longer than a fully assured one: %v", unknown)
	}

	// And a session started with no provider says so, rather than naming a band.
	dir := t.TempDir()
	_, sess := startedSession(t, dir)
	if sess.AssuranceBand != BandUnknown {
		t.Fatalf("a session with no assurance provider reported band %q", sess.AssuranceBand)
	}
}

func TestARotationSurvivesTheRestartToo(t *testing.T) {
	// The join the earlier tests did not cross. One restarted but never
	// activated; the other activated but marked rotation directly on a live
	// service. Between them they looked like they covered
	// start → restart → rotate → activate and covered neither half of it.
	//
	// The wait was made to survive a restart and the rotation gate was not, so
	// a session came back having forgotten its mandatory rotation was done and
	// demanded it again — on an agent where the rotation route may not even be
	// available, which makes the session permanently unactivatable.
	dir := t.TempDir()
	svc, sess := startedSession(t, dir)

	if _, err := svc.RecordRotation(sess.ID, RotationResult{AID: sess.IdentityAID}); err != nil {
		t.Fatal(err)
	}

	// The agent stops and starts.
	restarted := NewService(dir, nil, nil)
	if _, err := restarted.LoadSessions(); err != nil {
		t.Fatal(err)
	}

	got, err := restarted.GetSession(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.RotationDone {
		t.Fatal("the mandatory rotation was forgotten across a restart")
	}

	// And the gate agrees, which is what actually decides activation.
	if err := restarted.Rotation.RequireCompleted(sess.ID); err != nil {
		t.Fatalf("the rotation gate asks for it again after a restart: %v", err)
	}

	restarted.CancelGate.Now = func() time.Time { return time.Now().Add(96 * time.Hour) }
	if _, err := restarted.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic}); err != nil {
		t.Fatalf("a session that waited out its window still could not complete: %v", err)
	}
}

func TestACompletedRecoveryCannotBeRunAgain(t *testing.T) {
	// Activation rewrites the identity, the key event log, every restored file,
	// and re-seats the root seed. Running it twice rolls all of that back to
	// whatever the archive held, undoing key rotations and everything since.
	// The session was deleted from disk and left in memory holding its archive,
	// so a completed recovery could be replayed for the life of the process.
	dir := t.TempDir()
	svc, sess := startedSession(t, dir)
	svc.CancelGate.Now = func() time.Time { return time.Now().Add(96 * time.Hour) }
	svc.Rotation.MarkCompleted(sess.ID, RotationResult{})

	done, err := svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatal(err)
	}
	if done.State != SessionActivated {
		t.Fatalf("a finished recovery reports %q", done.State)
	}

	if _, err := svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic}); err == nil {
		t.Fatal("a completed recovery ran a second time")
	}

	// And nothing is left holding the archive.
	svc.mu.Lock()
	_, stillThere := svc.sessions[sess.ID]
	svc.mu.Unlock()
	if stillThere {
		t.Fatal("a completed recovery is still in memory with its archive")
	}
}

func TestAFinishedSessionKeepsTheStateItFinishedIn(t *testing.T) {
	// GetSession overwrote a terminal state with rotation_complete, so a screen
	// polling after activating could never see that it had worked — and the
	// natural response to that is to activate again.
	dir := t.TempDir()
	svc, sess := startedSession(t, dir)
	svc.CancelGate.Now = func() time.Time { return time.Now().Add(96 * time.Hour) }
	svc.Rotation.MarkCompleted(sess.ID, RotationResult{})

	done, err := svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatal(err)
	}
	if done.State != SessionActivated {
		t.Fatalf("activate returned %q", done.State)
	}
	// The session is gone once it completes, which is itself the answer a
	// caller needs; what must not happen is it reporting rotation_complete.
	if s, err := svc.GetSession(sess.ID); err == nil && s.State == SessionRotated {
		t.Fatal("a completed recovery reports rotation_complete, so success is invisible")
	}
}

func TestAnUnwantedRecoveryCanBeStopped(t *testing.T) {
	// The window's entire stated purpose is the time somebody who did NOT start
	// a recovery has to stop it, and nothing could. Restarting the agent used
	// to discard the session — the only lever anybody had — and making sessions
	// survive a restart removed even that.
	dir := t.TempDir()
	svc, sess := startedSession(t, dir)

	// No recovery phrase is required, and that is the point: the person
	// stopping this is by definition not the one who started it.
	cancelled, err := svc.Cancel(sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.State != SessionCancelled {
		t.Fatalf("a cancelled recovery reports %q", cancelled.State)
	}

	if _, err := svc.GetSession(sess.ID); err == nil {
		t.Fatal("a cancelled recovery is still there")
	}
	if _, err := os.Stat(filepath.Join(dir, "recovery_sessions", sess.ID+".json")); !os.IsNotExist(err) {
		t.Fatal("a cancelled recovery still holds the archive on disk")
	}

	// And it stays cancelled across a restart.
	restarted := NewService(dir, nil, nil)
	if n, err := restarted.LoadSessions(); err != nil || n != 0 {
		t.Fatalf("a cancelled recovery came back: %d %v", n, err)
	}
}

func TestAnArchiveThatNamesNoIdentityIsRefused(t *testing.T) {
	// The binding check in Activate is "the phrase must open the identity this
	// session was started for", and it is skipped when the session has no
	// identity. Start could produce exactly that: an identity section carrying
	// a blank AID overwrote a perfectly good manifest AID.
	dir := t.TempDir()
	svc := NewService(dir, nil, nil)
	sess, err := svc.Start(StartRequest{
		ArchiveB64: base64.StdEncoding.EncodeToString(buildTestArchive(t, testMnemonic, nil)),
		Mnemonic:   testMnemonic,
	})
	if err != nil {
		// An archive with no identity at all must be refused rather than
		// producing an unbound session.
		if !strings.Contains(err.Error(), "does not say which identity") {
			t.Fatalf("refused for the wrong reason: %v", err)
		}
		return
	}
	if sess.IdentityAID == "" {
		t.Fatal("a session was started that is bound to no identity")
	}
}

func TestARecoveryCanBeFoundAgainWithoutItsId(t *testing.T) {
	// A recovery was reachable only through the screen that started it. The
	// wait is measured in days and the session was deliberately made to survive
	// the agent restarting — but somebody who pressed back, or closed the app,
	// had no way to reach it again: the id lived in a widget and nothing could
	// rediscover it. The recovery could then be neither finished nor stopped
	// while the agent kept it alive and waiting, which defeats both halves of
	// what the wait is for.
	dir := t.TempDir()
	svc, sess := startedSession(t, dir)

	found := svc.InProgress()
	if len(found) != 1 || found[0].ID != sess.ID {
		t.Fatalf("a recovery in progress could not be found without its id: %+v", found)
	}
	// Enough to resume from, not just an id.
	if found[0].CompleteAfter == "" || found[0].IdentityAID == "" {
		t.Fatalf("the listing does not say what is waiting or for whom: %+v", found[0])
	}

	// It survives the restart too, which is the case that matters.
	restarted := NewService(dir, nil, nil)
	if _, err := restarted.LoadSessions(); err != nil {
		t.Fatal(err)
	}
	if again := restarted.InProgress(); len(again) != 1 || again[0].ID != sess.ID {
		t.Fatalf("after a restart it is unreachable again: %+v", again)
	}

	// And a finished one stops being offered, so nobody is invited to resume
	// something that already happened.
	waitedOutFor(t, restarted, sess)
	if _, err := restarted.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic}); err != nil {
		t.Fatal(err)
	}
	if left := restarted.InProgress(); len(left) != 0 {
		t.Fatalf("a completed recovery is still offered as resumable: %+v", left)
	}
}

func waitedOutFor(t *testing.T, svc *Service, sess *Session) {
	t.Helper()
	svc.CancelGate.Now = func() time.Time { return time.Now().Add(96 * time.Hour) }
	svc.Rotation.MarkCompleted(sess.ID, RotationResult{})
}

func TestAFailedRecoveryIsNotOfferedToResume(t *testing.T) {
	// Activated and cancelled sessions are deleted outright; a failure leaves
	// the record in place. A client asking what to resume was handed it, and
	// showed it as waiting with a live "finish" button — on a recovery that
	// was already over.
	dir := t.TempDir()
	svc, sess := startedSession(t, dir)

	svc.mu.Lock()
	svc.sessions[sess.ID].Session.State = SessionFailed
	svc.sessions[sess.ID].Session.Error = "the archive would not open"
	svc.mu.Unlock()

	if left := svc.InProgress(); len(left) != 0 {
		t.Fatalf("a failed recovery is offered as resumable: %+v", left)
	}

	// It is still readable by id, so somebody who has it can see what happened.
	got, err := svc.GetSession(sess.ID)
	if err != nil {
		t.Fatalf("a failed recovery became unreadable: %v", err)
	}
	if got.State != SessionFailed || got.Error == "" {
		t.Fatalf("the failure lost its reason: %+v", got)
	}
}
