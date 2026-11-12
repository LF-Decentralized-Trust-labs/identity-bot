package measurementlist

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"identity-agent-core/update"
)

var now = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

// A fixed key derived from a label, so the committed vectors are reproducible.
// Its private half is not secret and it signs nothing real.
func vectorKey(label string) (ed25519.PrivateKey, PinnedKey) {
	seed := sha256.Sum256([]byte(label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv, PinnedKey{ID: "test-publisher-1", Public: priv.Public().(ed25519.PublicKey)}
}

func meas(b byte) string { return strings.Repeat(hex.EncodeToString([]byte{b}), MeasurementSize) }

func baseDoc() map[string]any {
	return map[string]any{
		"list_version":   1,
		"sequence":       7,
		"published_at":   "2026-11-01T00:00:00Z",
		"expires_at":     "2026-12-01T00:00:00Z",
		"signing_key_id": "test-publisher-1",
		"images": map[string]any{
			"individual":   []string{meas(0x11), meas(0x12)},
			"organization": []string{meas(0x21)},
		},
	}
}

// sign is the publisher's side, in test only: the real signer is private.
func sign(t testing.TB, priv ed25519.PrivateKey, doc map[string]any) []byte {
	t.Helper()
	unsigned, _ := json.Marshal(doc)
	msg, err := SignedBytes(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	doc["signature"] = update.EncodeBase64URL(ed25519.Sign(priv, msg))
	out, _ := json.Marshal(doc)
	return out
}

func policy(k PinnedKey) Policy { return Policy{Key: k, Now: now} }

func TestAGenuineListVerifies(t *testing.T) {
	priv, key := vectorKey("a")
	l, err := Verify(sign(t, priv, baseDoc()), policy(key))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(l.Measurements("individual")); got != 2 {
		t.Fatalf("individual has %d measurements, want 2 (two live versions)", got)
	}
}

func TestATamperedListIsRefused(t *testing.T) {
	priv, key := vectorKey("a")
	raw := sign(t, priv, baseDoc())
	// Swap one accepted measurement for another, leaving the signature alone.
	tampered := []byte(strings.Replace(string(raw), meas(0x11), meas(0x99), 1))
	if string(tampered) == string(raw) {
		t.Fatal("test did not change the list")
	}
	if _, err := Verify(tampered, policy(key)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
	// Adding an entry is the attack that matters.
	d := baseDoc()
	signed := sign(t, priv, d)
	var m map[string]any
	json.Unmarshal(signed, &m)
	m["images"].(map[string]any)["individual"] = append(m["images"].(map[string]any)["individual"].([]any), meas(0x99))
	added, _ := json.Marshal(m)
	if _, err := Verify(added, policy(key)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("an appended measurement: got %v, want ErrBadSignature", err)
	}
}

func TestAListSignedByAnotherKeyIsRefused(t *testing.T) {
	other, _ := vectorKey("attacker")
	_, pinned := vectorKey("a")
	if _, err := Verify(sign(t, other, baseDoc()), policy(pinned)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
	// Same key, wrong id: realms with separate keys must not read each other.
	priv, key := vectorKey("a")
	d := baseDoc()
	d["signing_key_id"] = "dev-publisher-1"
	if _, err := Verify(sign(t, priv, d), policy(key)); !errors.Is(err, ErrWrongKeyID) {
		t.Fatalf("got %v, want ErrWrongKeyID", err)
	}
}

func TestAnOldListIsRefused(t *testing.T) {
	priv, key := vectorKey("a")
	raw := sign(t, priv, baseDoc()) // sequence 7
	p := policy(key)
	p.MinSequence = 8
	if _, err := Verify(raw, p); !errors.Is(err, ErrOldList) {
		t.Fatalf("got %v, want ErrOldList", err)
	}
	p.MinSequence = 7 // the same list again is not old
	if _, err := Verify(raw, p); err != nil {
		t.Fatalf("the current list was refused: %v", err)
	}
}

func TestAnExpiredListIsRefused(t *testing.T) {
	priv, key := vectorKey("a")
	p := policy(key)
	p.Now = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	if _, err := Verify(sign(t, priv, baseDoc()), p); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

func TestAMeasurementNotOnTheListIsNotAccepted(t *testing.T) {
	priv, key := vectorKey("a")
	l, _ := Verify(sign(t, priv, baseDoc()), policy(key))
	has := func(kind string, m []byte) bool {
		for _, a := range l.Measurements(kind) {
			if string(a) == string(m) {
				return true
			}
		}
		return false
	}
	unlisted, _ := hex.DecodeString(meas(0x99))
	listed, _ := hex.DecodeString(meas(0x11))
	orgs, _ := hex.DecodeString(meas(0x21))
	if has("individual", unlisted) {
		t.Error("an unlisted measurement was accepted")
	}
	if !has("individual", listed) {
		t.Error("a listed measurement was not accepted")
	}
	if has("individual", orgs) {
		t.Error("an organization image was accepted for an individual")
	}
	if len(l.Measurements("unknown-kind")) != 0 || (*List)(nil).Measurements("individual") != nil {
		t.Error("a kind the list does not name must accept nothing")
	}
}

func TestNoPinnedKeyVerifiesNothing(t *testing.T) {
	priv, _ := vectorKey("a")
	if _, err := Verify(sign(t, priv, baseDoc()), Policy{Now: now}); !errors.Is(err, ErrNoKey) {
		t.Fatalf("got %v, want ErrNoKey", err)
	}
	if _, err := Pinned(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("a build with no key: %v", err)
	}
}

func TestAPublishedTestKeyCannotBePinned(t *testing.T) {
	if _, err := ParseKeyHex("x", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"); err == nil {
		t.Fatal("the RFC 8032 test key was accepted as a publisher key")
	}
}

func TestMalformedContentIsRefusedEvenWhenSigned(t *testing.T) {
	priv, key := vectorKey("a")
	cases := map[string]func(map[string]any){
		"short measurement": func(d map[string]any) { d["images"] = map[string]any{"individual": []string{meas(0x11)[:90]}} },
		"upper case": func(d map[string]any) {
			d["images"] = map[string]any{"individual": []string{strings.ToUpper(meas(0xab))}}
		},
		"duplicate": func(d map[string]any) { d["images"] = map[string]any{"individual": []string{meas(1), meas(1)}} },
		"shared across kinds": func(d map[string]any) {
			d["images"] = map[string]any{"individual": []string{meas(1)}, "organization": []string{meas(1)}}
		},
		"empty kind":      func(d map[string]any) { d["images"] = map[string]any{"individual": []string{}} },
		"no kinds":        func(d map[string]any) { d["images"] = map[string]any{} },
		"unknown version": func(d map[string]any) { d["list_version"] = 2 },
		"unknown field":   func(d map[string]any) { d["extra"] = true },
		"zero sequence":   func(d map[string]any) { d["sequence"] = 0 },
		"expiry first":    func(d map[string]any) { d["expires_at"] = "2026-10-01T00:00:00Z" },
		"future":          func(d map[string]any) { d["published_at"] = "2026-11-13T00:00:00Z" },
	}
	for name, mut := range cases {
		d := baseDoc()
		mut(d)
		if _, err := Verify(sign(t, priv, d), policy(key)); err == nil {
			t.Errorf("%s: a signed but malformed list was accepted", name)
		}
	}
	for _, raw := range []string{"", "null", "[]", "{", "{}"} {
		if _, err := Verify([]byte(raw), policy(key)); err == nil {
			t.Errorf("%q was accepted", raw)
		}
	}
}

// A signature made for a list is not a signature on anything else, and the
// reverse: the same key signing the bare canonical bytes is not a list.
func TestTheSignatureIsBoundToThisKindOfDocument(t *testing.T) {
	priv, key := vectorKey("a")
	d := baseDoc()
	unsigned, _ := json.Marshal(d)
	canonical, _ := update.CanonicalizeWithoutField(unsigned, "signature")
	d["signature"] = update.EncodeBase64URL(ed25519.Sign(priv, canonical)) // no prefix
	raw, _ := json.Marshal(d)
	if _, err := Verify(raw, policy(key)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestTheFloorRefusesAnOldListAcrossRestarts(t *testing.T) {
	priv, key := vectorKey("a")
	dir := t.TempDir()
	path, floor := filepath.Join(dir, "list.json"), filepath.Join(dir, "floor")
	d7, d9, d8 := baseDoc(), baseDoc(), baseDoc()
	d9["sequence"], d8["sequence"] = 9, 8
	old := sign(t, priv, d7)
	os.WriteFile(path, sign(t, priv, d9), 0o600)
	if _, err := LoadFile(path, floor, key, now); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, old, 0o600) // a stale copy put back
	if _, err := LoadFile(path, floor, key, now); !errors.Is(err, ErrOldList) {
		t.Fatalf("got %v, want ErrOldList", err)
	}
	os.WriteFile(path, sign(t, priv, d8), 0o600)
	if _, err := LoadFile(path, floor, key, now); !errors.Is(err, ErrOldList) {
		t.Fatalf("sequence 8 after 9: got %v", err)
	}
	os.WriteFile(floor, []byte("garbage"), 0o600) // damage is not "nothing seen"
	os.WriteFile(path, sign(t, priv, d9), 0o600)
	if _, err := LoadFile(path, floor, key, now); err == nil {
		t.Fatal("a damaged floor was read as zero")
	}
}

// The committed vectors are what other implementations check against. They are
// reproduced byte for byte from the fixed key, so they cannot drift unseen.
func TestTheCommittedVectorsVerifyAndAreReproducible(t *testing.T) {
	priv, key := vectorKey("measurement-list-vectors-v1")
	want := sign(t, priv, baseDoc())
	if os.Getenv("WRITE_VECTORS") != "" {
		os.WriteFile("testdata/valid.json", want, 0o644)
		os.WriteFile("testdata/publisher_key.hex", []byte(hex.EncodeToString(key.Public)+"\n"), 0o644)
	}
	got, err := os.ReadFile("testdata/valid.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatal("testdata/valid.json differs from what the fixed key produces; rerun with WRITE_VECTORS=1 only if the format changed on purpose")
	}
	hexKey, _ := os.ReadFile("testdata/publisher_key.hex")
	if strings.TrimSpace(string(hexKey)) != hex.EncodeToString(key.Public) {
		t.Fatal("testdata/publisher_key.hex does not match the vector key")
	}
	if _, err := Verify(got, policy(key)); err != nil {
		t.Fatal(err)
	}
}
