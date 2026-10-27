package agentmachine

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNeedsAreKnownOnceAndInOrder(t *testing.T) {
	got, err := Needs([]string{" Xcode", "screen", "", "SCREEN", "toolchain"})
	if err != nil || strings.Join(got, ",") != "screen,toolchain,xcode" {
		t.Fatalf("got %v %v", got, err)
	}
	if _, err := Needs([]string{"gpu"}); err == nil {
		t.Fatal("an unknown need was taken")
	}
	if got, _ := Needs(nil); got == nil || len(got) != 0 {
		t.Fatalf("no needs is %v, not an empty list", got)
	}
	if m := Missing([]string{"screen", "xcode"}, []string{"screen", "toolchain"}); strings.Join(m, ",") != "xcode" {
		t.Fatalf("missing: %v", m)
	}
}

func TestAMachineNameIsSafeToHandToAProgram(t *testing.T) {
	for in, prefix := range map[string]string{
		"Dev worker":             "agent-dev-worker-",
		"  ; rm -rf / ":          "agent-rm-rf-",
		"Ünïcode only ✓":         "agent-n-code-only-",
		"✓✓✓":                    "agent-",
		strings.Repeat("a", 100): "agent-" + strings.Repeat("a", 24) + "-",
	} {
		n, err := machineName(in)
		if err != nil || !strings.HasPrefix(n, prefix) || !ValidMachineName(n) {
			t.Fatalf("%q became %q (%v)", in, n, err)
		}
	}
	for _, bad := range []string{"", "-x", "a b", "a;b", "A", strings.Repeat("a", 41), "../x"} {
		if ValidMachineName(bad) {
			t.Fatalf("%q was taken as a machine name", bad)
		}
	}
}

// A provider moves a request only forward, never to ready, and only its own.
func TestAProviderMovesOnlyItsOwnRequestsForward(t *testing.T) {
	s := NewStore(t.TempDir())
	now := time.Now()
	if _, err := s.Ask("a1", "Dev", "p1", []string{"toolchain"}, "owner", now); err == nil {
		t.Fatal("a provider that never offered was asked")
	}
	if err := s.Seen(Provider{Body: "p1", Name: "Host", Offers: []string{"toolchain"}, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ask("a1", "Dev", "p1", []string{"screen"}, "owner", now); !errors.Is(err, ErrNotOffered) {
		t.Fatalf("asked for what it does not offer: %v", err)
	}
	j, err := s.Ask("a1", "Dev", "p1", []string{"toolchain"}, "owner", now)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Changed():
		t.Fatal("changed fired with nothing new")
	default:
	}
	if _, err := s.Report(j.ID, "p2", StateMaking, "", nil, now); err == nil {
		t.Fatal("another provider reported on it")
	}
	if _, err := s.Report(j.ID, "p1", StateReady, "", nil, now); !errors.Is(err, ErrMove) {
		t.Fatalf("a provider made it ready: %v", err)
	}
	if _, err := s.Report(j.ID, "p1", StateMaking, "", nil, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Report(j.ID, "p1", StateEnrolling, "", []string{"a", "b"}, now); err == nil {
		t.Fatal("two words were taken as a machine's six")
	}
	if _, err := s.Report(j.ID, "p1", StateEnrolling, "", strings.Fields("a b c d e f"), now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Bound(j.ID, "b1", now); err != nil {
		t.Fatal(err)
	}
	s.Approved("b1", now)
	if j, _ = s.Get(j.ID); j.State != StateReady {
		t.Fatalf("approved, it is %s", j.State)
	}
	if len(s.ForProvider("p1")) != 0 {
		t.Fatal("a ready machine was handed to its provider as work")
	}
	if j, _ = s.Remove(j.ID, now); j.State != StateRemoving || len(s.ForProvider("p1")) != 1 {
		t.Fatalf("removed, it is %s", j.State)
	}
	if j, err = s.Report(j.ID, "p1", StateRemoved, "destroyed", nil, now); err != nil || !j.Done() {
		t.Fatalf("%v %v", j, err)
	}
	// A request never picked up is simply over when cancelled.
	k, _ := s.Ask("a1", "Dev", "p1", nil, "owner", now)
	if k, _ = s.Remove(k.ID, now); k.State != StateRemoved {
		t.Fatalf("cancelled before it was made, it is %s", k.State)
	}
}
