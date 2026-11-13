package measurementlist

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Version 2 vectors: files the Go and the Dart verifiers both read
// (packages/agent_client/test), each with what it must produce. They are
// reproduced from the fixed vector key (WRITE_VECTORS=1 rewrites them), signed
// under the same key as testdata/publisher_key.hex, and read at 2026-11-12T12:00Z.
// What a vector expects is written here by hand, never taken from a verifier.

type v2Expect struct {
	Measurement string `json:"measurement"`
	Environment string `json:"environment"`
	SVN         uint32 `json:"svn"`
	SMT         bool   `json:"smt"`
	// Retired is "" (not retired), "update" or "revoked".
	Retired     string `json:"retired"`
	SourceUntil string `json:"source_until,omitempty"`
}

type v2Vector struct {
	File        string     `json:"file"`
	Refusal     string     `json:"refusal"` // name of the error; "" means it verifies
	MinSequence int64      `json:"min_sequence,omitempty"`
	Entries     []v2Expect `json:"entries,omitempty"`
	Note        string     `json:"note"`
}

func entryV2(image string, b byte, env string, svn any, smt any, retired any) map[string]any {
	e := entry(image, b)
	e["environment"], e["svn"], e["smt"], e["retired"] = env, svn, smt, retired
	return e
}

func docV2(images map[string]any) map[string]any {
	d := baseDoc()
	d["list_version"], d["sequence"], d["images"] = 2, 8, images
	return d
}

func oneV2(mutate func(e map[string]any)) map[string]any {
	e := entryV2("individual-v19", 0x11, "production", 6, true, nil)
	mutate(e)
	return docV2(map[string]any{"individual": []any{e}})
}

func v2Vectors(t *testing.T) []struct {
	v   v2Vector
	raw []byte
} {
	priv, _ := vectorKey("measurement-list-vectors-v1")
	until := "2026-11-20T00:00:00Z"
	at := "2026-11-10T00:00:00Z"
	retUpdate := map[string]any{"kind": "update", "at": at, "source_until": until}

	valid := docV2(map[string]any{
		"individual": []any{
			entryV2("individual-v20", 0x12, "production", 6, true, nil),
			entryV2("individual-v19", 0x11, "production", 5, true, retUpdate),
		},
		"organization": []any{entryV2("organization-v10", 0x21, "development", 1, false, nil)},
	})
	unreadable := docV2(map[string]any{"individual": []any{
		entryV2("a", 0x31, "production", 1, true, map[string]any{"kind": "sunset", "at": at}),
		entryV2("b", 0x32, "production", 1, true, map[string]any{"kind": "update", "at": at}),
		entryV2("c", 0x33, "production", 1, true, "retired"),
		entryV2("d", 0x34, "production", 1, true, map[string]any{"KIND": "update", "at": at, "source_until": until}),
		entryV2("e", 0x35, "production", 1, true, map[string]any{"kind": "update", "at": at, "source_until": until, "extra": 1}),
		entryV2("f", 0x36, "production", 1, true, map[string]any{"kind": "update", "source_until": until}),
		entryV2("g", 0x37, "production", 1, true, map[string]any{"kind": "revoked", "at": at}),
		entryV2("h", 0x38, "production", 1, true, nil),
	}})

	tampered := []byte(strings.Replace(string(sign(t, priv, oneV2(func(map[string]any) {}))), `"svn":6`, `"svn":9`, 1))
	v1With := oneV2(func(map[string]any) {})
	v1With["list_version"] = 1
	v3 := baseDoc()
	v3["list_version"] = 3
	dup := docV2(map[string]any{"individual": []any{
		entryV2("a", 0x11, "production", 1, true, nil), entryV2("b", 0x11, "production", 2, true, nil)}})

	ex := func(m byte, env string, svn uint32, smt bool, ret, src string) v2Expect {
		return v2Expect{Measurement: meas(m), Environment: env, SVN: svn, SMT: smt, Retired: ret, SourceUntil: src}
	}
	revoked := func(m byte) v2Expect { return ex(m, "production", 1, true, "revoked", "") }

	return []struct {
		v   v2Vector
		raw []byte
	}{
		{v2Vector{File: "valid.json", Note: "a live image, one retired for update with an end to its use as a source, and a development image",
			Entries: []v2Expect{ex(0x12, "production", 6, true, "", ""), ex(0x11, "production", 5, true, "update", until), ex(0x21, "development", 1, false, "", "")}}, sign(t, priv, valid)},
		{v2Vector{File: "unreadable_retired.json", Note: "each unreadable retired revokes its own entry and no other: an unknown kind, update with no source_until, not an object, a key in another case, an unknown field, no at; a written revoked stays revoked; the last entry is untouched",
			Entries: []v2Expect{revoked(0x31), revoked(0x32), revoked(0x33), revoked(0x34), revoked(0x35), revoked(0x36), revoked(0x37), ex(0x38, "production", 1, true, "", "")}}, sign(t, priv, unreadable)},
		{v2Vector{File: "tampered_svn.json", Refusal: "ErrBadSignature", Note: "the security version changed after signing"}, tampered},
		{v2Vector{File: "no_svn.json", Refusal: "ErrBadEntry", Note: "an entry that gives no svn"}, sign(t, priv, oneV2(func(e map[string]any) { delete(e, "svn") }))},
		{v2Vector{File: "null_smt.json", Refusal: "ErrBadEntry", Note: "an entry whose smt is null"}, sign(t, priv, oneV2(func(e map[string]any) { e["smt"] = nil }))},
		{v2Vector{File: "no_environment.json", Refusal: "ErrBadEntry", Note: "an entry that gives no environment"}, sign(t, priv, oneV2(func(e map[string]any) { delete(e, "environment") }))},
		{v2Vector{File: "environment_staging.json", Refusal: "ErrBadEntry", Note: "an environment that is neither production nor development"}, sign(t, priv, oneV2(func(e map[string]any) { e["environment"] = "staging" }))},
		{v2Vector{File: "svn_negative.json", Refusal: "ErrMalformed", Note: "svn below zero"}, sign(t, priv, oneV2(func(e map[string]any) { e["svn"] = -1 }))},
		{v2Vector{File: "svn_too_large.json", Refusal: "ErrMalformed", Note: "svn above 4294967295"}, sign(t, priv, oneV2(func(e map[string]any) { e["svn"] = int64(4294967296) }))},
		{v2Vector{File: "svn_a_string.json", Refusal: "ErrMalformed", Note: "svn written as text"}, sign(t, priv, oneV2(func(e map[string]any) { e["svn"] = "6" }))},
		{v2Vector{File: "v1_carrying_v2_fields.json", Refusal: "ErrMalformed", Note: "list_version 1 whose entry carries version 2 fields"}, sign(t, priv, v1With)},
		{v2Vector{File: "unknown_entry_field.json", Refusal: "ErrMalformed", Note: "a version 2 entry with a field no version knows"}, sign(t, priv, oneV2(func(e map[string]any) { e["colour"] = "red" }))},
		{v2Vector{File: "duplicate_measurement.json", Refusal: "ErrDuplicateEntries", Note: "one measurement listed twice"}, sign(t, priv, dup)},
		{v2Vector{File: "version_3.json", Refusal: "ErrUnknownVersion", Note: "a list version nobody reads yet"}, sign(t, priv, v3)},
	}
}

func TestTheVersionTwoVectorsAreRefusedAndReadAsTheirFilesSay(t *testing.T) {
	_, key := vectorKey("measurement-list-vectors-v1")
	vectors := v2Vectors(t)
	dir := "testdata/v2"
	var manifest []v2Vector
	for _, c := range vectors {
		manifest = append(manifest, c.v)
	}
	manifestJSON, _ := json.MarshalIndent(manifest, "", "  ")
	manifestJSON = append(manifestJSON, '\n')
	if os.Getenv("WRITE_VECTORS") != "" {
		os.MkdirAll(dir, 0o755)
		for _, c := range vectors {
			os.WriteFile(filepath.Join(dir, c.v.File), c.raw, 0o644)
		}
		os.WriteFile(filepath.Join(dir, "expectations.json"), manifestJSON, 0o644)
	}
	got, err := os.ReadFile(filepath.Join(dir, "expectations.json"))
	if err != nil || string(got) != string(manifestJSON) {
		t.Fatal("testdata/v2/expectations.json is missing or differs; rerun with WRITE_VECTORS=1 only if intended")
	}
	for _, c := range vectors {
		v := c.v
		raw, err := os.ReadFile(filepath.Join(dir, v.File))
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != string(c.raw) {
			t.Errorf("%s differs from what the fixed key produces", v.File)
		}
		l, err := Verify(raw, Policy{Key: key, MinSequence: v.MinSequence, Now: now})
		if v.Refusal != "" {
			if want := refusals[v.Refusal]; want == nil || !errors.Is(err, want) {
				t.Errorf("%s: got %v, want %s", v.File, err, v.Refusal)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", v.File, err)
			continue
		}
		seen := 0
		for _, es := range l.Images {
			for _, e := range es {
				seen++
				var want *v2Expect
				for i := range v.Entries {
					if v.Entries[i].Measurement == hexOf(e.Measurement) {
						want = &v.Entries[i]
					}
				}
				if want == nil {
					t.Errorf("%s: unexpected entry %x", v.File, e.Measurement[:1])
					continue
				}
				ret, src := "", ""
				if e.Retired != nil {
					ret = e.Retired.Kind
					if !e.Retired.SourceUntil.IsZero() {
						src = e.Retired.SourceUntil.UTC().Format(time.RFC3339)
					}
				}
				if e.Environment != want.Environment || e.SVN != want.SVN || e.SMT != want.SMT || ret != want.Retired || src != want.SourceUntil {
					t.Errorf("%s: entry %x read as %s/%d/%v/%q/%q, want %+v", v.File, e.Measurement[:1], e.Environment, e.SVN, e.SMT, ret, src, *want)
				}
			}
		}
		if seen != len(v.Entries) {
			t.Errorf("%s: %d entries read, %d expected", v.File, seen, len(v.Entries))
		}
	}
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }
