// Package contractcheck holds a published JSON Schema to the Go types it
// describes.
//
// A schema in contracts/ is what another implementation is written from; the
// Go types are what this one actually sends. Nothing keeps the two together on
// its own, so a field added in Go and not in the schema, or made optional in
// one and required in the other, would go unnoticed until another
// implementation refused a message. Each package that publishes a schema calls
// this from a test, so the drift fails here first.
//
// It checks names, not value types: every property the schema declares is a
// field the type writes, every field the type writes is declared, a field the
// type always writes is required and one it may leave out is not, and the
// schema refuses anything undeclared.
//
// What it does not see, so a type relying on any of these needs its own check:
//   - an embedded (anonymous) struct, whose fields encoding/json promotes into
//     the parent; it is read as one field named after the embedded type;
//   - the omitzero option, which it treats like a field always written;
//   - nested objects: each definition is checked against one Go type, so a
//     nested struct is checked only where the test names it against its own
//     definition, which is why ObjectDefs exists.
package contractcheck

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// Schema is a published schema document, read from disk.
type Schema struct {
	Path string
	Defs map[string]Def `json:"$defs"`
}

// Def is one definition in a schema.
type Def struct {
	Type                 any                        `json:"type"`
	Properties           map[string]json.RawMessage `json:"properties"`
	Required             []string                   `json:"required"`
	AdditionalProperties *bool                      `json:"additionalProperties"`
}

// Read reads a schema document.
func Read(path string) (*Schema, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := &Schema{Path: path}
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// Matches reports every way the definition named def disagrees with the Go
// type v, which is a struct or a pointer to one. An empty result means they
// agree.
func (s *Schema) Matches(def string, v any) []string {
	d, ok := s.Defs[def]
	if !ok {
		return []string{fmt.Sprintf("%s: no definition %q", s.Path, def)}
	}
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	where := fmt.Sprintf("%s $defs/%s (Go %s)", s.Path, def, t)
	var out []string
	if d.AdditionalProperties == nil || *d.AdditionalProperties {
		out = append(out, where+": does not refuse undeclared fields (additionalProperties must be false)")
	}
	written, always := fieldsOf(t)
	required := map[string]bool{}
	for _, r := range d.Required {
		required[r] = true
	}
	for _, name := range sortedKeys(written) {
		if _, declared := d.Properties[name]; !declared {
			out = append(out, fmt.Sprintf("%s: Go writes %q, the schema does not declare it", where, name))
			continue
		}
		if always[name] && !required[name] {
			out = append(out, fmt.Sprintf("%s: Go always writes %q, the schema does not require it", where, name))
		}
		if !always[name] && required[name] {
			out = append(out, fmt.Sprintf("%s: Go may leave out %q, the schema requires it", where, name))
		}
	}
	for _, name := range sortedKeys(d.Properties) {
		if !written[name] {
			out = append(out, fmt.Sprintf("%s: the schema declares %q, Go never writes it", where, name))
		}
	}
	return out
}

// fieldsOf is every JSON field a struct writes, and which of them it always
// writes (no omitempty).
func fieldsOf(t reflect.Type) (written, always map[string]bool) {
	written, always = map[string]bool{}, map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if name == "" {
			name = f.Name
		}
		written[name] = true
		if !strings.Contains(","+opts+",", ",omitempty,") {
			always[name] = true
		}
	}
	return written, always
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ObjectDefs are the names of the definitions that describe a JSON object. A
// test holds each to a Go type, and fails on any it does not name, so a
// definition added to the schema cannot go unchecked.
func (s *Schema) ObjectDefs() []string {
	var out []string
	for name, d := range s.Defs {
		if d.Type == "object" || d.Properties != nil {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Unheld are the object definitions held names none of.
func (s *Schema) Unheld(held map[string]any) []string {
	var out []string
	for _, name := range s.ObjectDefs() {
		if _, ok := held[name]; !ok {
			out = append(out, fmt.Sprintf("%s: $defs/%s is an object no test holds to a Go type", s.Path, name))
		}
	}
	return out
}

// Fataler is the part of testing.TB that Writing needs.
type Fataler interface {
	Helper()
	Fatal(args ...any)
}

// Writing reports whether a test should write its published files instead of
// only checking them: IA_WRITE_CONTRACTS=1. Never in CI, where writing would
// make the check agree with whatever the code now does.
func Writing(t Fataler) bool {
	t.Helper()
	if os.Getenv("IA_WRITE_CONTRACTS") != "1" {
		return false
	}
	if os.Getenv("CI") != "" {
		t.Fatal("IA_WRITE_CONTRACTS is set in CI: published contracts are written by a person and reviewed, never regenerated by the check that guards them")
	}
	return true
}

// Tester is the part of testing.TB that Independently needs.
type Tester interface {
	Helper()
	Skip(args ...any)
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// Unavailable skips an independent check whose tools are not installed, or
// fails it when IA_REQUIRE_INDEPENDENT_CHECK=1: a runner that sets it has
// promised the tools, so a check that did not run is a check that failed.
func Unavailable(t Tester, why string) {
	t.Helper()
	if os.Getenv("IA_REQUIRE_INDEPENDENT_CHECK") == "1" {
		t.Fatal(why + ", and IA_REQUIRE_INDEPENDENT_CHECK=1 requires the independent check to run")
	}
	t.Skip(why)
}

// Independently runs contracts/check_ai_agent_vectors.py, an implementation
// written from the schemas' prose in Python rather than from this code, over a
// vector file. If it and the Go code disagree, the prose no longer says what
// the code does. Where Python, or the blake3 module it needs, is not
// installed, see Unavailable.
func Independently(t Tester, contracts, vectors string) {
	t.Helper()
	IndependentlyWith(t, filepath.Join(contracts, "check_ai_agent_vectors.py"), vectors, "blake3")
}

// IndependentlyWith runs another independent check, the Python script at
// script, over a vector file, where Python and each of the modules it needs
// are installed; see Unavailable for where they are not.
func IndependentlyWith(t Tester, script, vectors string, modules ...string) {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		Unavailable(t, "python3 is not installed")
		return
	}
	for _, m := range modules {
		if exec.Command(py, "-c", "import "+m).Run() != nil {
			Unavailable(t, "the python "+m+" module is not installed (pip install "+m+")")
			return
		}
	}
	out, err := exec.Command(py, "-I", script, vectors).CombinedOutput()
	if err != nil {
		t.Fatalf("the independent check disagrees:\n%s", out)
	}
}
