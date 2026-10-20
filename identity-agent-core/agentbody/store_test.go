package agentbody

import (
	"errors"
	"testing"
	"time"
)

func pendingFor(agent, host string) Binding {
	return Binding{AgentAssetID: agent, Agent: "E" + agent, Keys: Keys{Host: host}}
}

// A secret works once. A second machine using the same secret is refused,
// however quickly it follows the first.
func TestASecretIsSpentOnFirstUse(t *testing.T) {
	s := NewStore(t.TempDir())
	now := time.Now()
	secret, _, err := s.Invite("a1", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(secret, pendingFor("a1", "BHOST1"), now); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := s.Claim(secret, pendingFor("a1", "BHOST2"), now); !errors.Is(err, ErrInvitation) {
		t.Fatalf("a reused secret gave %v", err)
	}
}

func TestASecretIsRefusedWhenExpiredReplacedOrForAnotherAgent(t *testing.T) {
	s := NewStore(t.TempDir())
	now := time.Now()
	old, _, _ := s.Invite("a1", now)
	if _, err := s.Claim(old, pendingFor("a1", "BH"), now.Add(EnrolmentWindow+time.Second)); !errors.Is(err, ErrInvitation) {
		t.Fatalf("an expired secret gave %v", err)
	}
	newer, _, _ := s.Invite("a1", now)
	if _, err := s.Claim(old, pendingFor("a1", "BH"), now); !errors.Is(err, ErrInvitation) {
		t.Fatalf("a replaced secret gave %v", err)
	}
	if _, err := s.Claim(newer, pendingFor("a2", "BH"), now); !errors.Is(err, ErrInvitation) {
		t.Fatalf("a secret for another AI agent gave %v", err)
	}
}

// One key speaks for one AI agent.
func TestOneKeyIsTheBodyOfOneAgent(t *testing.T) {
	s := NewStore(t.TempDir())
	now := time.Now()
	s1, _, _ := s.Invite("a1", now)
	b, err := s.Claim(s1, pendingFor("a1", "BH"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decide(b.ID, "a1", StateActive, "BCONTROLLER", "ECRED", now); err != nil {
		t.Fatal(err)
	}
	s2, _, _ := s.Invite("a2", now)
	if _, err := s.Claim(s2, pendingFor("a2", "BH"), now); !errors.Is(err, ErrHostTaken) {
		t.Fatalf("one key became the body of two AI agents: %v", err)
	}
	if got, ok := s.ActiveByHost("BH"); !ok || got.AgentAssetID != "a1" {
		t.Fatalf("the live binding is %+v", got)
	}
	if _, err := s.Revoke(b.ID, "a1", now); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ActiveByHost("BH"); ok {
		t.Fatal("a revoked binding is still live")
	}
	if _, err := s.Decide(b.ID, "a1", StateActive, "x", "", now); err == nil {
		t.Fatal("a revoked binding was decided again")
	}
}
