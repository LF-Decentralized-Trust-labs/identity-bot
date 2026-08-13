package backup

import (
	"testing"
	"time"

	"identity-agent-core/store"
)

// A scheduled backup actually takes one.
//
// It did not. Nothing ever called SetMnemonicProvider outside tests, so every
// scheduled and every triggered backup reached one line, logged a skip, and
// returned — on every agent, for as long as the scheduler has existed. The
// trigger route reported "scheduled" regardless, so nothing surfaced it.
//
// This asserts the thing that was missing: that asking for a backup results in
// an export being attempted.
func TestAScheduledBackupActuallyRuns(t *testing.T) {
	dir := t.TempDir()
	st, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Skipf("data store unavailable: %v", err)
	}
	svc := NewService(dir, st)
	cfgStore := svc.ConfigStore
	cfg, _ := cfgStore.LoadConfig()
	cfg.Enabled = true
	cfg.DefaultTiers = []string{"tier1"}
	if err := cfgStore.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}

	// A seed, the way a real agent has one: on its own disk, not in somebody's
	// memory.
	svc.Scheduler.SetSeedProvider(func() ([]byte, error) {
		return make([]byte, 64), nil
	})

	svc.Scheduler.SetDebounceInterval(5 * time.Millisecond)
	svc.NotifyEvent(EventManual)

	// Wait for a RECORDED RUN, not for the function to be entered.
	//
	// The first version of this waited on the after-run hook, which fires
	// before the seed is even looked for — so it passed with the fix removed
	// and proved only that runBackup was called. What matters is that an export
	// happened, and history is where that is written down.
	deadline := time.Now().Add(5 * time.Second)
	for {
		hist, err := cfgStore.LoadHistory()
		if err == nil && len(hist) > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("asking for a backup recorded no run at all — which is what happened on " +
				"every agent, silently, because nothing supplied the seed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An agent with no way to reach its seed says so, rather than reporting success.
//
// The old behaviour is the reason this went unnoticed: the trigger answered
// "scheduled" and the only evidence was a log line five minutes later.
func TestAnAgentThatCannotReachItsSeedSaysSo(t *testing.T) {
	svc := NewService(t.TempDir(), nil)
	if err := svc.Scheduler.CanRun(); err == nil {
		t.Fatal("an agent with no seed provider reported that it could take a backup")
	}

	svc.Scheduler.SetSeedProvider(func() ([]byte, error) { return make([]byte, 64), nil })
	if err := svc.Scheduler.CanRun(); err != nil {
		t.Fatalf("an agent that can read its seed reported that it could not: %v", err)
	}
}
