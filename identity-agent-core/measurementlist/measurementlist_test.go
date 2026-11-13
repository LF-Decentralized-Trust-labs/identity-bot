package measurementlist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

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
		"d":            "E-the-credential-said",
		"dt":           "2026-11-01T00:00:00.000000+00:00",
		"sequence":     7,
		"published_at": "2026-11-01T00:00:00Z",
		"expires_at":   "2026-12-01T00:00:00Z",
		"images": map[string]any{
			"individual":   []any{entry("individual-v19", 0x11), entry("individual-v20", 0x12)},
			"organization": []any{entry("organization-v10", 0x21)},
		},
	}
}

// read is the core's own path: the attribute block of a list credential read
// strictly, then held to the rules. The digest stands for the credential.
func read(t testing.TB, doc map[string]any, r Rules) (*List, error) {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ContentOfAttributes(raw)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return FromContent(c, hex.EncodeToString(sum[:]), r)
}

func rules() Rules { return Rules{Now: now} }

func TestAGenuineListIsRead(t *testing.T) {
	l, err := read(t, baseDoc(), rules())
	if err != nil {
		t.Fatal(err)
	}
	if got := len(l.Measurements("individual")); got != 2 {
		t.Fatalf("individual has %d measurements, want 2 (two live versions)", got)
	}
}

func TestAnOldListIsRefused(t *testing.T) {
	r := rules()
	r.MinSequence = 8
	if _, err := read(t, baseDoc(), r); !errors.Is(err, ErrOldList) { // sequence 7
		t.Fatalf("got %v, want ErrOldList", err)
	}
	r.MinSequence = 7 // the same list again is not old
	if _, err := read(t, baseDoc(), r); err != nil {
		t.Fatalf("the current list was refused: %v", err)
	}
}

func TestADifferentListAtTheSameSequenceIsRefused(t *testing.T) {
	first, err := read(t, baseDoc(), rules())
	if err != nil {
		t.Fatal(err)
	}
	other := baseDoc()
	other["images"] = map[string]any{"individual": []any{entry("individual-v19", 0x55)}}
	r := rules()
	r.MinSequence, r.SeenDigest = 7, first.Digest
	if _, err := read(t, other, r); !errors.Is(err, ErrConflictingList) {
		t.Fatalf("got %v, want ErrConflictingList", err)
	}
	if _, err := read(t, baseDoc(), r); err != nil {
		t.Fatalf("the list accepted at that sequence was refused again: %v", err)
	}
}

func TestAnExpiredListIsRefused(t *testing.T) {
	r := rules()
	r.Now = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	if _, err := read(t, baseDoc(), r); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

func TestAListDatedInTheFutureIsRefused(t *testing.T) {
	d := baseDoc()
	d["published_at"] = "2026-11-13T00:00:00Z"
	if _, err := read(t, d, rules()); !errors.Is(err, ErrNotYetPublished) {
		t.Fatalf("got %v, want ErrNotYetPublished", err)
	}
}

func TestAMeasurementNotOnTheListIsNotAccepted(t *testing.T) {
	l, _ := read(t, baseDoc(), rules())
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

// During an update both images are valid; an entry is retired by its date, and
// a retired entry is carried but not accepted.
func TestEntriesAreAcceptedOnlyInsideTheirWindow(t *testing.T) {
	d := baseDoc()
	old, next, future := entry("individual-v19", 0x11), entry("individual-v20", 0x12), entry("individual-v21", 0x13)
	old["valid_until"] = "2026-11-20T00:00:00Z"
	future["valid_from"] = "2026-12-01T00:00:00Z"
	d["images"] = map[string]any{"individual": []any{old, next, future}}
	l, err := read(t, d, rules())
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
	l, err := read(t, baseDoc(), rules())
	if err != nil {
		t.Fatal(err)
	}
	e := l.Images["individual"][0]
	if e.Image != "individual-v19" || e.ComputedFrom.VCPUs != 1 || e.ComputedFrom.CPUModel != "EPYC-v4" ||
		e.ComputedFrom.OVMFSHA256 != strings.Repeat("0a", 32) || e.ComputedFrom.CmdlineSHA256 != strings.Repeat("0c", 32) {
		t.Fatalf("entry lost its provenance: %+v", e)
	}
}

func TestMalformedContentIsRefused(t *testing.T) {
	one := func(mut func(e map[string]any)) func(map[string]any) {
		return func(d map[string]any) {
			e := entry("i", 1)
			mut(e)
			d["images"] = map[string]any{"individual": []any{e}}
		}
	}
	cf := func(k string, v any) func(map[string]any) {
		return one(func(e map[string]any) {
			if v == nil {
				delete(e["computed_from"].(map[string]any), k)
			} else {
				e["computed_from"].(map[string]any)[k] = v
			}
		})
	}
	cases := map[string]func(map[string]any){
		"short measurement": one(func(e map[string]any) { e["measurement"] = meas(0x11)[:90] }),
		"upper case":        one(func(e map[string]any) { e["measurement"] = strings.ToUpper(meas(0xab)) }),
		"duplicate": func(d map[string]any) {
			d["images"] = map[string]any{"individual": []any{entry("a", 1), entry("b", 1)}}
		},
		"shared across kinds": func(d map[string]any) {
			d["images"] = map[string]any{"individual": []any{entry("a", 1)}, "organization": []any{entry("b", 1)}}
		},
		"empty kind":                   func(d map[string]any) { d["images"] = map[string]any{"individual": []any{}} },
		"no kinds":                     func(d map[string]any) { d["images"] = map[string]any{} },
		"no image name":                one(func(e map[string]any) { e["image"] = "" }),
		"no firmware hash":             cf("ovmf_sha256", nil),
		"no cpu model":                 cf("cpu_model", ""),
		"zero vcpus":                   cf("vcpus", 0),
		"no command-line hash":         cf("cmdline_sha256", nil),
		"no validity start":            one(func(e map[string]any) { e["valid_from"] = "" }),
		"window ends before it starts": one(func(e map[string]any) { e["valid_until"] = "2026-10-01T00:00:00Z" }),
		"unknown entry field":          one(func(e map[string]any) { e["note"] = "x" }),
		"unknown version":              func(d map[string]any) { d["list_version"] = 3 },
		"unknown field":                func(d map[string]any) { d["extra"] = true },
		"zero sequence":                func(d map[string]any) { d["sequence"] = 0 },
		"expiry first":                 func(d map[string]any) { d["expires_at"] = "2026-10-01T00:00:00Z" },
		"no credential date":           func(d map[string]any) { d["dt"] = "" },
		"not whole seconds":            func(d map[string]any) { d["published_at"] = "2026-11-01T00:00:00.5Z" },
		"not in UTC":                   func(d map[string]any) { d["expires_at"] = "2026-12-01T00:00:00+01:00" },
	}
	for name, mut := range cases {
		d := baseDoc()
		mut(d)
		if _, err := read(t, d, rules()); err == nil {
			t.Errorf("%s: a malformed list was accepted", name)
		}
	}
	for _, raw := range []string{"", "null", "[]", "{", "{}"} {
		if c, err := ContentOfAttributes([]byte(raw)); err == nil {
			if _, err := FromContent(c, "x", rules()); err == nil {
				t.Errorf("%q was accepted", raw)
			}
		}
	}
}
