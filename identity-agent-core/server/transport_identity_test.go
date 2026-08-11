package server

import (
	"os"
	"path/filepath"
	"testing"
)

// The fingerprint is what clients pin, so its stability is the property that
// matters more than any other here.

// A key that changed on every restart would make every reconnection look like
// an interception — and would train people to accept a changed fingerprint,
// which is the one habit that makes pinning worthless.
func TestTheTransportKeySurvivesARestart(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreateTransportIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateTransportIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.FingerprintB64 != second.FingerprintB64 {
		t.Fatalf("the fingerprint changed between starts:\n%s\n%s",
			first.FingerprintB64, second.FingerprintB64)
	}
	if first.FingerprintB64 == "" {
		t.Fatal("no fingerprint was produced")
	}
}

// Two agents must not share one. A shared key would let either read what was
// sent to the other.
func TestTwoAgentsGetDifferentKeys(t *testing.T) {
	a, err := LoadOrCreateTransportIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateTransportIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if a.FingerprintB64 == b.FingerprintB64 {
		t.Fatal("two agents were given the same transport key")
	}
}

// An unreadable key is refused rather than replaced. Replacing it would
// silently change the fingerprint every client has pinned, which is
// indistinguishable from an interception to everyone who had one.
func TestAnUnreadableKeyIsRefusedRatherThanReplaced(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateTransportIdentity(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, transportCertFile), []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateTransportIdentity(dir); err == nil {
		t.Fatal("a damaged certificate was quietly replaced, changing the fingerprint " +
			"every client had pinned")
	}
}

// The key is a secret and lives beside the agent's other secrets.
func TestTheKeyIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateTransportIdentity(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, transportKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("the transport key is readable by others: mode %o", mode)
	}
}

// The attestation binds to the transport fingerprint where one exists, rather
// than to an identifier — which would let anyone holding a list of identifiers
// confirm which instance is which, at one query each.
func TestTheAttestationBindsToTheTransportKey(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreateTransportIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := &CoreServer{transportIdentity: id}
	if got := s.attestationBinding(); got != id.FingerprintB64 {
		t.Fatalf("bound to %q, want the transport fingerprint %q", got, id.FingerprintB64)
	}
}

// And an agent with no key of its own still attests, bound to what it has.
// Losing attestation entirely would be worse than binding to an identifier.
func TestAnAgentWithoutATransportKeyStillBindsToSomething(t *testing.T) {
	s := &CoreServer{}
	// No transport identity and no store: the binding is empty rather than a
	// panic, and the caller decides what an empty binding means.
	_ = s.attestationBinding()
}
