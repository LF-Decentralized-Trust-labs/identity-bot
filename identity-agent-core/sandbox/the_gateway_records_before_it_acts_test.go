package sandbox

import (
	"context"
	"errors"
	"identity-agent-core/activitylog"
	"identity-agent-core/activitylog/activitylogtest"
	"identity-agent-core/permission"
	"testing"
)

// The gateway records a governed action before it runs it, in the activity
// log, and does not run what it cannot record.

// newLoggingManager is a manager whose log is signed by a signer that keeps
// where its chain begins.
func newLoggingManager(t *testing.T) (*Manager, *activitylogtest.KeepingSigner) {
	t.Helper()
	m, err := NewManager(ManagerConfig{DataDir: t.TempDir(), ManifestsDir: t.TempDir()})
	if err != nil {
		t.Skipf("sandbox manager unavailable: %v", err)
	}
	k := activitylogtest.NewKeepingSigner(t)
	m.log.SetEventSigner(k)
	return m, k
}

// actingManager is a logging manager with one capability a local owner may
// run, routed to a fake executor.
func actingManager(t *testing.T) (*Manager, *activitylogtest.KeepingSigner, *fakeInvoker) {
	t.Helper()
	m, k := newLoggingManager(t)
	f := &fakeInvoker{result: &InvokeResult{CapabilityID: "act.now", Status: 200, Body: []byte(`{}`)}}
	m.mu.Lock()
	m.invoker = f
	if m.manifests == nil {
		m.manifests = map[string]*AppManifest{}
	}
	m.manifests["act"] = &AppManifest{ID: "act", Provides: []ProvidedCapability{{ID: "act.now"}}}
	m.mu.Unlock()
	return m, k, f
}

func act(m *Manager) error {
	_, err := m.InvokeCapability(context.Background(), permission.CallerContext{CallerAID: "local-owner"}, "act.now", []byte(`{}`))
	return err
}

// When the record cannot be written first, the action does not run: not when
// the signer is unavailable, and not when the log itself cannot be read.
func TestAnActionThatCannotBeRecordedDoesNotRun(t *testing.T) {
	t.Run("the signer is unavailable", func(t *testing.T) {
		m, k, f := actingManager(t)
		activitylogtest.WriteEvents(t, m.log, "n.one")
		k.Fail = true
		if err := act(m); !errors.Is(err, activitylog.ErrNotRecorded) || f.called {
			t.Fatalf("ran without a record: called=%v err=%v", f.called, err)
		}
	})
	t.Run("the signer is unavailable before anything was signed", func(t *testing.T) {
		m, k, f := actingManager(t)
		k.Fail = true
		if err := act(m); !errors.Is(err, activitylog.ErrNotRecorded) || f.called {
			t.Fatalf("ran without a record: called=%v err=%v", f.called, err)
		}
	})
	t.Run("the log cannot be read", func(t *testing.T) {
		m, _, f := actingManager(t)
		activitylogtest.WriteEvents(t, m.log, "n.one")
		m.log.DB().Exec(`ALTER TABLE invocation_log RENAME TO invocation_log_gone`)
		if err := act(m); !errors.Is(err, activitylog.ErrNotRecorded) || f.called {
			t.Fatalf("ran without a record: called=%v err=%v", f.called, err)
		}
	})
	t.Run("a recorded action runs, its result after its intent", func(t *testing.T) {
		m, k, f := actingManager(t)
		if err := act(m); err != nil || !f.called {
			t.Fatalf("a recordable action did not run: %v", err)
		}
		events, _ := m.log.QueryInvocationEvents(activitylog.InvocationEventFilter{CapabilityID: "act.now"})
		if len(events) != 2 || events[1].ResultStatus != "started" || events[0].IntentEventID != events[1].ID {
			t.Fatalf("want an intent row then its result, got %+v", events)
		}
		if faults, err := m.log.VerifyChain(k.Keys, &k.Start); err != nil || len(faults) != 0 {
			t.Fatalf("%+v %v", faults, err)
		}
	})
}

// A row whose record is gone is a fault at that row, not a stop to the log:
// actions are still recorded and run, and the rows after it verify.
func TestAMissingRecordIsAFaultNotAStop(t *testing.T) {
	m, k, f := actingManager(t)
	activitylogtest.WriteEvents(t, m.log, "o.one", "o.two")
	m.log.DB().Exec(`UPDATE invocation_log SET event_json = NULL WHERE id = 2`)
	if err := act(m); err != nil || !f.called {
		t.Fatalf("a missing record stopped the log: %v", err)
	}
	activitylogtest.WriteEvents(t, m.log, "o.after")
	faults, err := m.log.VerifyChain(k.Keys, &k.Start)
	if err != nil {
		t.Fatalf("a missing record made the check fail outright: %v", err)
	}
	if len(faults) != 1 || faults[0].ID != 2 {
		t.Fatalf("want one fault, at the missing row, got %+v", faults)
	}
	if events, err := m.log.QueryInvocationEvents(activitylog.InvocationEventFilter{}); err != nil || len(events) != 5 {
		t.Fatalf("the missing row should still be listed: %d %v", len(events), err)
	}
}
