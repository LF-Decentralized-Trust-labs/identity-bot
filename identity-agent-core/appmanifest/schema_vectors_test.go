package appmanifest

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// A published manifest is accepted or refused by the published schema exactly
// as by DecodeManifest and Validate, and as the vector file says. The schema
// is what another implementation is written from, so a disagreement here is a
// manifest that one reader installs and another refuses.
func TestThePublishedSchemaAgreesWithValidateOnEveryVector(t *testing.T) {
	raw, err := os.ReadFile("../contracts/app-manifest/app-manifest.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	sv := &schemaValidator{root: doc, patterns: map[string]*regexp.Regexp{}}

	vs := readAppVectors(t)
	if len(vs) < 100 {
		t.Fatalf("%d vectors", len(vs))
	}
	for _, v := range vs {
		var instance any
		if err := json.Unmarshal(v.Manifest, &instance); err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		schemaErr := sv.validate(doc, instance, "")

		var goErr error
		if m, err := DecodeManifest(v.Manifest); err != nil {
			goErr = err
		} else {
			goErr = m.Validate()
		}

		want := v.Outcome == "accepted"
		if got := schemaErr == nil; got != want {
			t.Errorf("%s: the vector file says %s, the schema says %v", v.Name, v.Outcome, schemaErr)
		}
		if got := goErr == nil; got != want {
			t.Errorf("%s: the vector file says %s, DecodeManifest and Validate say %v", v.Name, v.Outcome, goErr)
		}
	}
	if len(sv.faults) > 0 {
		t.Errorf("the schema uses what the test's validator does not read:\n  %s", strings.Join(sv.faults, "\n  "))
	}
}

// A minimal JSON Schema (2020-12) validator, enough for this one schema. It
// reads every keyword the schema uses and records, rather than ignoring, one
// it does not know, so that a keyword added to the schema cannot go unchecked.
// Patterns are Go regular expressions: the schema avoids look-ahead so that
// any engine reads it, and "\uXXXX" is rewritten to Go's "\x{XXXX}".
type schemaValidator struct {
	root     map[string]any
	patterns map[string]*regexp.Regexp
	faults   []string
}

var knownKeywords = map[string]bool{
	"$schema": true, "$id": true, "$defs": true, "$ref": true, "title": true, "description": true,
	"type": true, "enum": true, "const": true, "required": true, "properties": true, "additionalProperties": true,
	"items": true, "pattern": true, "minLength": true, "minimum": true, "maximum": true, "exclusiveMinimum": true,
	"minItems": true, "maxItems": true, "maxProperties": true, "uniqueItems": true, "propertyNames": true,
	"allOf": true, "anyOf": true, "oneOf": true, "if": true, "then": true, "else": true, "not": true, "contains": true,
}

func (s *schemaValidator) fault(f string, args ...any) {
	msg := fmt.Sprintf(f, args...)
	for _, have := range s.faults {
		if have == msg {
			return
		}
	}
	s.faults = append(s.faults, msg)
}

func (s *schemaValidator) regexp(p string) *regexp.Regexp {
	if re, ok := s.patterns[p]; ok {
		return re
	}
	goPattern := regexp.MustCompile(`\\u([0-9a-fA-F]{4})`).ReplaceAllString(p, `\x{$1}`)
	re, err := regexp.Compile(goPattern)
	if err != nil {
		s.fault("pattern %q is not read by a regular expression engine without look-ahead: %v", p, err)
		re = regexp.MustCompile(`^\b$`) // never matches
	}
	s.patterns[p] = re
	return re
}

// validate returns nil if instance satisfies schema, else why not.
func (s *schemaValidator) validate(schema map[string]any, instance any, path string) error {
	for k := range schema {
		if !knownKeywords[k] {
			s.fault("keyword %q", k)
		}
	}
	if ref, ok := schema["$ref"].(string); ok {
		name, found := strings.CutPrefix(ref, "#/$defs/")
		target, _ := s.root["$defs"].(map[string]any)[name].(map[string]any)
		if !found || target == nil {
			s.fault("$ref %q", ref)
		} else if err := s.validate(target, instance, path); err != nil {
			return err
		}
	}
	bad := func(f string, a ...any) error { return fmt.Errorf("%s: %s", path, fmt.Sprintf(f, a...)) }

	if t, ok := schema["type"]; ok {
		types := []any{t}
		if l, isList := t.([]any); isList {
			types = l
		}
		matched := false
		for _, ty := range types {
			matched = matched || isType(instance, ty.(string))
		}
		if !matched {
			return bad("is not of type %v", t)
		}
	}
	if e, ok := schema["enum"].([]any); ok {
		in := false
		for _, v := range e {
			in = in || reflect.DeepEqual(v, instance)
		}
		if !in {
			return bad("%v is not one of %v", instance, e)
		}
	}
	if c, ok := schema["const"]; ok && !reflect.DeepEqual(c, instance) {
		return bad("is not %v", c)
	}

	switch v := instance.(type) {
	case string:
		if p, ok := schema["pattern"].(string); ok && !s.regexp(p).MatchString(v) {
			return bad("%q does not match %s", v, p)
		}
		if n, ok := schema["minLength"].(float64); ok && float64(utf8.RuneCountInString(v)) < n {
			return bad("is shorter than %v", n)
		}
	case float64:
		if n, ok := schema["minimum"].(float64); ok && v < n {
			return bad("%v is below %v", v, n)
		}
		if n, ok := schema["maximum"].(float64); ok && v > n {
			return bad("%v is above %v", v, n)
		}
		if n, ok := schema["exclusiveMinimum"].(float64); ok && v <= n {
			return bad("%v is not above %v", v, n)
		}
	case []any:
		if n, ok := schema["minItems"].(float64); ok && float64(len(v)) < n {
			return bad("has fewer than %v items", n)
		}
		if n, ok := schema["maxItems"].(float64); ok && float64(len(v)) > n {
			return bad("has more than %v items", n)
		}
		if u, _ := schema["uniqueItems"].(bool); u {
			for i := range v {
				for j := i + 1; j < len(v); j++ {
					if reflect.DeepEqual(v[i], v[j]) {
						return bad("lists %v twice", v[i])
					}
				}
			}
		}
		if items, ok := schema["items"].(map[string]any); ok {
			for i, item := range v {
				if err := s.validate(items, item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
		if c, ok := schema["contains"].(map[string]any); ok {
			found := false
			for _, item := range v {
				found = found || s.validate(c, item, path) == nil
			}
			if !found {
				return bad("has no item matching contains")
			}
		}
	case map[string]any:
		for _, r := range asStrings(schema["required"]) {
			if _, ok := v[r]; !ok {
				return bad("lacks required key %q", r)
			}
		}
		if n, ok := schema["maxProperties"].(float64); ok && float64(len(v)) > n {
			return bad("has more than %v keys", n)
		}
		props, _ := schema["properties"].(map[string]any)
		for _, k := range sortedMapKeys(v) {
			here := k
			if path != "" {
				here = path + "." + k
			}
			if pn, ok := schema["propertyNames"].(map[string]any); ok {
				if err := s.validate(pn, k, here); err != nil {
					return err
				}
			}
			if ps, ok := props[k].(map[string]any); ok {
				if err := s.validate(ps, v[k], here); err != nil {
					return err
				}
			} else if ap, present := schema["additionalProperties"]; present {
				switch a := ap.(type) {
				case bool:
					if !a {
						return fmt.Errorf("%s: not a key the schema declares", here)
					}
				case map[string]any:
					if err := s.validate(a, v[k], here); err != nil {
						return err
					}
				}
			}
		}
	}

	for _, sub := range subschemas(schema["allOf"]) {
		if err := s.validate(sub, instance, path); err != nil {
			return err
		}
	}
	if subs := subschemas(schema["anyOf"]); subs != nil {
		ok := false
		for _, sub := range subs {
			ok = ok || s.validate(sub, instance, path) == nil
		}
		if !ok {
			return bad("matches none of anyOf")
		}
	}
	if subs := subschemas(schema["oneOf"]); subs != nil {
		n := 0
		for _, sub := range subs {
			if s.validate(sub, instance, path) == nil {
				n++
			}
		}
		if n != 1 {
			return bad("matches %d of oneOf, want 1", n)
		}
	}
	if not, ok := schema["not"].(map[string]any); ok && s.validate(not, instance, path) == nil {
		return bad("matches a schema it must not match")
	}
	if cond, ok := schema["if"].(map[string]any); ok {
		if s.validate(cond, instance, path) == nil {
			if then, ok := schema["then"].(map[string]any); ok {
				return s.validate(then, instance, path)
			}
		} else if els, ok := schema["else"].(map[string]any); ok {
			return s.validate(els, instance, path)
		}
	}
	return nil
}

func isType(v any, t string) bool {
	switch t {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "null":
		return v == nil
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		f, ok := v.(float64)
		return ok && f == math.Trunc(f)
	}
	return false
}

func asStrings(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		out = append(out, x.(string))
	}
	return out
}

func subschemas(v any) []map[string]any {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(l))
	for _, x := range l {
		out = append(out, x.(map[string]any))
	}
	return out
}

func sortedMapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
