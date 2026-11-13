package measurementlist

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
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

func entry(image string, b byte) map[string]any {
	return map[string]any{
		"image":       image,
		"measurement": meas(b),
		"computed_from": map[string]any{
			"ovmf_sha256":    strings.Repeat("0a", 32),
			"vcpus":          1,
			"cpu_model":      "EPYC-v4",
			"cmdline_sha256": strings.Repeat("0c", 32),
		},
		"valid_from":  "2026-11-01T00:00:00Z",
		"valid_until": nil,
	}
}

func baseDoc() map[string]any {
	return map[string]any{
		"list_version":   1,
		"sequence":       7,
		"published_at":   "2026-11-01T00:00:00Z",
		"expires_at":     "2026-12-01T00:00:00Z",
		"signing_key_id": "test-publisher-1",
		"images": map[string]any{
			"individual":   []any{entry("individual-v19", 0x11), entry("individual-v20", 0x12)},
			"organization": []any{entry("organization-v10", 0x21)},
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
	m["images"].(map[string]any)["individual"] = append(m["images"].(map[string]any)["individual"].([]any), entry("individual-v21", 0x99))
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

// Item 7: during an update both images are valid; an entry is retired by its
// date, and a retired entry is carried but not accepted.
func TestEntriesAreAcceptedOnlyInsideTheirWindow(t *testing.T) {
	priv, key := vectorKey("a")
	d := baseDoc()
	old, next, future := entry("individual-v19", 0x11), entry("individual-v20", 0x12), entry("individual-v21", 0x13)
	old["valid_until"] = "2026-11-20T00:00:00Z"
	future["valid_from"] = "2026-12-01T00:00:00Z"
	d["images"] = map[string]any{"individual": []any{old, next, future}}
	l, err := Verify(sign(t, priv, d), policy(key))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(l.Measurements("individual")); got != 2 {
		t.Fatalf("during the update %d measurements are accepted, want the old and the new (2)", got)
	}
	at := func(y int, m time.Month, day int) int {
		return len(l.MeasurementsAt("individual", time.Date(y, m, day, 0, 0, 0, 0, time.UTC)))
	}
	if got := at(2026, 11, 21); got != 1 {
		t.Errorf("after the old entry's date %d are accepted, want only the new one", got)
	}
	if got := at(2026, 12, 2); got != 2 {
		t.Errorf("when the next image starts %d are accepted, want 2", got)
	}
	if got := at(2026, 10, 1); got != 0 {
		t.Errorf("before any window %d are accepted, want none", got)
	}
}

func TestEveryEntryKeepsWhatItWasComputedFrom(t *testing.T) {
	priv, key := vectorKey("a")
	l, err := Verify(sign(t, priv, baseDoc()), policy(key))
	if err != nil {
		t.Fatal(err)
	}
	e := l.Images["individual"][0]
	if e.Image != "individual-v19" || e.ComputedFrom.VCPUs != 1 || e.ComputedFrom.CPUModel != "EPYC-v4" ||
		e.ComputedFrom.OVMFSHA256 != strings.Repeat("0a", 32) || e.ComputedFrom.CmdlineSHA256 != strings.Repeat("0c", 32) {
		t.Fatalf("entry lost its provenance: %+v", e)
	}
}

func TestNoPinnedKeyVerifiesNothing(t *testing.T) {
	priv, _ := vectorKey("a")
	if _, err := Verify(sign(t, priv, baseDoc()), Policy{Now: now}); !errors.Is(err, ErrNoKey) {
		t.Fatalf("got %v, want ErrNoKey", err)
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
		"short measurement": func(d map[string]any) {
			e := entry("i", 0x11)
			e["measurement"] = meas(0x11)[:90]
			d["images"] = map[string]any{"individual": []any{e}}
		},
		"upper case": func(d map[string]any) {
			e := entry("i", 0xab)
			e["measurement"] = strings.ToUpper(meas(0xab))
			d["images"] = map[string]any{"individual": []any{e}}
		},
		"duplicate": func(d map[string]any) {
			d["images"] = map[string]any{"individual": []any{entry("a", 1), entry("b", 1)}}
		},
		"shared across kinds": func(d map[string]any) {
			d["images"] = map[string]any{"individual": []any{entry("a", 1)}, "organization": []any{entry("b", 1)}}
		},
		"empty kind": func(d map[string]any) { d["images"] = map[string]any{"individual": []any{}} },
		"no kinds":   func(d map[string]any) { d["images"] = map[string]any{} },
		"no image name": func(d map[string]any) {
			e := entry("", 1)
			d["images"] = map[string]any{"individual": []any{e}}
		},
		"no firmware hash": func(d map[string]any) {
			e := entry("i", 1)
			delete(e["computed_from"].(map[string]any), "ovmf_sha256")
			d["images"] = map[string]any{"individual": []any{e}}
		},
		"no cpu model": func(d map[string]any) {
			e := entry("i", 1)
			e["computed_from"].(map[string]any)["cpu_model"] = ""
			d["images"] = map[string]any{"individual": []any{e}}
		},
		"zero vcpus": func(d map[string]any) {
			e := entry("i", 1)
			e["computed_from"].(map[string]any)["vcpus"] = 0
			d["images"] = map[string]any{"individual": []any{e}}
		},
		"no command-line hash": func(d map[string]any) {
			e := entry("i", 1)
			delete(e["computed_from"].(map[string]any), "cmdline_sha256")
			d["images"] = map[string]any{"individual": []any{e}}
		},
		"no validity start": func(d map[string]any) {
			e := entry("i", 1)
			e["valid_from"] = ""
			d["images"] = map[string]any{"individual": []any{e}}
		},
		"window ends before it starts": func(d map[string]any) {
			e := entry("i", 1)
			e["valid_until"] = "2026-10-01T00:00:00Z"
			d["images"] = map[string]any{"individual": []any{e}}
		},
		"unknown entry field": func(d map[string]any) {
			e := entry("i", 1)
			e["note"] = "x"
			d["images"] = map[string]any{"individual": []any{e}}
		},
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

