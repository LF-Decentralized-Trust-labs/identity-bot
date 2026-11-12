package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"identity-agent-core/measurementlist"
	"identity-agent-core/update"
)

// The signed list is the policy when it verifies; the environment's list is
// only the bootstrap for when none does. A list that fails is never widened
// by, and never narrows, the bootstrap.

type listFixture struct {
	dir  string
	priv ed25519.PrivateKey
	key  measurementlist.PinnedKey
}

func newListFixture(t *testing.T, label string) *listFixture {
	t.Helper()
	seed := sha256.Sum256([]byte(label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	f := &listFixture{dir: t.TempDir(), priv: priv,
		key: measurementlist.PinnedKey{ID: "test-publisher-1", Public: priv.Public().(ed25519.PublicKey)}}
	old := pinnedPublisherKey
	pinnedPublisherKey = func() (measurementlist.PinnedKey, error) { return f.key, nil }
	t.Cleanup(func() { pinnedPublisherKey = old })
	t.Setenv("AGENT_MEASUREMENT_LIST_FILE", filepath.Join(f.dir, "list.json"))
	t.Setenv("AGENT_ACCEPTED_MEASUREMENTS", "")
	return f
}

func (f *listFixture) publish(t *testing.T, seq int, images map[string][]string, signWith ed25519.PrivateKey) []byte {
	t.Helper()
	now := time.Now().UTC()
	entries := map[string][]map[string]any{}
	for kind, ms := range images {
		for i, m := range ms {
			entries[kind] = append(entries[kind], map[string]any{
				"image": fmt.Sprintf("%s-v%d", kind, i+1), "measurement": m,
				"computed_from": map[string]any{
					"ovmf_sha256": strings.Repeat("0a", 32), "vcpus": 1, "cpu_model": "EPYC-v4",
					"cmdline_sha256": strings.Repeat("0c", 32),
				},
				"valid_from": now.Add(-2 * time.Hour).Format(time.RFC3339), "valid_until": nil,
			})
		}
	}
	doc := map[string]any{"list_version": 1, "sequence": seq,
		"published_at":   now.Add(-time.Hour).Format(time.RFC3339),
		"expires_at":     now.Add(24 * time.Hour).Format(time.RFC3339),
		"signing_key_id": "test-publisher-1", "images": entries}
	unsigned, _ := json.Marshal(doc)
	msg, err := measurementlist.SignedBytes(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	doc["signature"] = update.EncodeBase64URL(ed25519.Sign(signWith, msg))
	raw, _ := json.Marshal(doc)
	if err := os.WriteFile(filepath.Join(f.dir, "list.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return raw
}

func serverAccepting(m [][]byte) *CoreServer {
	return &CoreServer{localOwnerSecret: testOwnerSecret, AcceptedMeasurements: m}
}

func TestAVerifiedListIsThePolicyAndTheBootstrapIsNotAddedToIt(t *testing.T) {
	f := newListFixture(t, "a")
	t.Setenv("AGENT_ACCEPTED_MEASUREMENTS", aMeasurement(0x77))
	f.publish(t, 3, map[string][]string{"individual": {aMeasurement(0x11), aMeasurement(0x12)}}, f.priv)

	got, err := acceptedMeasurements(f.dir, "individual", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s := serverAccepting(got)
	for _, b := range []byte{0x11, 0x12} {
		if !s.acceptableMeasurement(mustHex(t, aMeasurement(b))) {
			t.Errorf("listed measurement %#x refused", b)
		}
	}
	if s.acceptableMeasurement(mustHex(t, aMeasurement(0x99))) {
		t.Error("a measurement not on the list was accepted")
	}
	if s.acceptableMeasurement(mustHex(t, aMeasurement(0x77))) {
		t.Error("the bootstrap was still honoured beside a verified list")
	}
}

func TestATamperedListFallsBackToTheBootstrapAndAddsNothing(t *testing.T) {
	f := newListFixture(t, "a")
	t.Setenv("AGENT_ACCEPTED_MEASUREMENTS", aMeasurement(0x77))
	raw := f.publish(t, 3, map[string][]string{"individual": {aMeasurement(0x11)}}, f.priv)
	os.WriteFile(filepath.Join(f.dir, "list.json"),
		[]byte(strings.Replace(string(raw), aMeasurement(0x11), aMeasurement(0x99), 1)), 0o600)

	s := serverAccepting(mustAccepted(t, f.dir))
	if s.acceptableMeasurement(mustHex(t, aMeasurement(0x99))) {
		t.Fatal("a measurement from a tampered list was accepted")
	}
	if !s.acceptableMeasurement(mustHex(t, aMeasurement(0x77))) {
		t.Error("the bootstrap should stand when no list verifies")
	}
}

func TestAListFromTheWrongKeyIsNotUsed(t *testing.T) {
	f := newListFixture(t, "a")
	seed := sha256.Sum256([]byte("attacker"))
	f.publish(t, 3, map[string][]string{"individual": {aMeasurement(0x99)}}, ed25519.NewKeyFromSeed(seed[:]))
	// No bootstrap either: nothing may be accepted.
	s := serverAccepting(mustAccepted(t, f.dir))
	if s.acceptableMeasurement(mustHex(t, aMeasurement(0x99))) {
		t.Fatal("a list signed by an unpinned key was accepted")
	}
}

func TestAnOldListIsNotUsedAfterANewerOne(t *testing.T) {
	f := newListFixture(t, "a")
	t.Setenv("AGENT_ACCEPTED_MEASUREMENTS", "")
	f.publish(t, 9, map[string][]string{"individual": {aMeasurement(0x12)}}, f.priv)
	mustAccepted(t, f.dir) // records sequence 9
	f.publish(t, 4, map[string][]string{"individual": {aMeasurement(0x11)}}, f.priv)
	s := serverAccepting(mustAccepted(t, f.dir))
	if s.acceptableMeasurement(mustHex(t, aMeasurement(0x11))) {
		t.Fatal("an image only an older list named was accepted")
	}
}

func TestAVerifiedListThatNamesNothingForThisKindRefusesEverything(t *testing.T) {
	f := newListFixture(t, "a")
	t.Setenv("AGENT_ACCEPTED_MEASUREMENTS", aMeasurement(0x77))
	f.publish(t, 3, map[string][]string{"organization": {aMeasurement(0x21)}}, f.priv)
	s := serverAccepting(mustAccepted(t, f.dir)) // this agent is an individual
	for _, b := range []byte{0x21, 0x77} {
		if s.acceptableMeasurement(mustHex(t, aMeasurement(b))) {
			t.Errorf("%#x accepted though the verified list names nothing for an individual", b)
		}
	}
}

func TestNoListFileMeansTheBootstrapAlone(t *testing.T) {
	f := newListFixture(t, "a")
	t.Setenv("AGENT_ACCEPTED_MEASUREMENTS", aMeasurement(0x77))
	s := serverAccepting(mustAccepted(t, f.dir)) // list.json does not exist
	if !s.acceptableMeasurement(mustHex(t, aMeasurement(0x77))) {
		t.Error("the bootstrap was not used")
	}
}

func mustAccepted(t *testing.T, dir string) [][]byte {
	t.Helper()
	m, err := acceptedMeasurements(dir, "individual", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func mustHex(t *testing.T, h string) []byte {
	t.Helper()
	m, err := parseMeasurements([]string{h})
	if err != nil {
		t.Fatal(err)
	}
	return m[0]
}
