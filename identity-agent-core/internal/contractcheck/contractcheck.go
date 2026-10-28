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
package contractcheck

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
)

// Schema is a published schema document, read from disk.
type Schema struct {
	Path string
	Defs map[string]Def `json:"$defs"`
}

// Def is one object definition in a schema.
type Def struct {
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
