package enrolsecret

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func open(t *testing.T) (*Store, string) {
	p := filepath.Join(t.TempDir(), "secrets.json")
	return Open(p), p
}

func TestAStoredSecretIsNeverRecoverableFromTheStore(t *testing.T) {
	s, p := open(t)
	secret, e, err := s.Issue("a", time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatalf("the file holds the secret: %s", raw)
	}
	if !strings.Contains(string(raw), Digest(secret)) || e.Digest != Digest(secret) {
		t.Fatal("the file should hold the digest")
	}
	// The digest is not itself a secret that claims.
	if _, err := s.Claim(e.Digest, "", t0); !errors.Is(err, ErrUnusable) {
		t.Fatalf("claiming with the stored digest: %v", err)
	}
}

func TestASecretIsGoodOnce(t *testing.T) {
	s, _ := open(t)
	secret, _, _ := s.Issue("a", time.Hour, t0)
	if _, err := s.Claim(secret, "a", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(secret, "a", t0); !errors.Is(err, ErrUnusable) {
		t.Fatalf("reuse: %v", err)
	}
}

func TestANewerSecretVoidsTheOlderForTheSameSubjectOnly(t *testing.T) {
	s, _ := open(t)
	old, _, _ := s.Issue("a", time.Hour, t0)
	other, _, _ := s.Issue("b", time.Hour, t0)
	newer, _, _ := s.Issue("a", time.Hour, t0)
	if _, err := s.Claim(old, "a", t0); !errors.Is(err, ErrUnusable) {
		t.Fatalf("the older secret still works: %v", err)
	}
	if _, err := s.Claim(newer, "a", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(other, "b", t0); err != nil {
		t.Fatalf("another subject's secret was voided: %v", err)
	}
}

func TestAnExpiredSecretIsRefusedAndPruned(t *testing.T) {
	s, p := open(t)
	secret, _, _ := s.Issue("a", time.Minute, t0)
	if _, err := s.Claim(secret, "a", t0.Add(time.Minute)); !errors.Is(err, ErrUnusable) {
		t.Fatalf("expired: %v", err)
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), Digest(secret)) {
		t.Fatalf("an expired secret is still stored: %s", raw)
	}
}

func TestASpentSecretIsNotKept(t *testing.T) {
	s, p := open(t)
	secret, _, _ := s.Issue("a", time.Hour, t0)
	s.Claim(secret, "a", t0)
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), Digest(secret)) {
		t.Fatalf("a spent secret is still stored: %s", raw)
	}
}

func TestASecretForAnotherSubjectIsRefusedAndNotSpent(t *testing.T) {
	s, _ := open(t)
	secret, _, _ := s.Issue("a", time.Hour, t0)
	if _, err := s.Claim(secret, "b", t0); !errors.Is(err, ErrUnusable) {
		t.Fatalf("wrong subject: %v", err)
	}
	if _, err := s.Claim(secret, "a", t0); err != nil {
		t.Fatalf("a refused claim spent the secret: %v", err)
	}
}

func TestReleaseHandsBackUnlessSuperseded(t *testing.T) {
	s, _ := open(t)
	secret, _, _ := s.Issue("a", time.Hour, t0)
	e, _ := s.Claim(secret, "", t0)
	if err := s.Release(e, t0); err != nil {
		t.Fatal(err)
	}
	e, err := s.Claim(secret, "", t0)
	if err != nil {
		t.Fatalf("released secret does not work: %v", err)
	}
	newer, _, _ := s.Issue("a", time.Hour, t0)
	if err := s.Release(e, t0); !errors.Is(err, ErrUnusable) {
		t.Fatalf("a superseded secret came back: %v", err)
	}
	if _, err := s.Claim(secret, "", t0); !errors.Is(err, ErrUnusable) {
		t.Fatal("superseded secret works")
	}
	if _, err := s.Claim(newer, "a", t0); err != nil {
		t.Fatal(err)
	}
}

func TestVoidEndsOnlyThatSecret(t *testing.T) {
	s, _ := open(t)
	a, ea, _ := s.Issue("", time.Hour, t0)
	b, _, _ := s.Issue("", time.Hour, t0)
	if err := s.Void(ea.Digest, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(a, "", t0); !errors.Is(err, ErrUnusable) {
		t.Fatal("voided secret works")
	}
	if _, err := s.Claim(b, "", t0); err != nil {
		t.Fatal(err)
	}
}
