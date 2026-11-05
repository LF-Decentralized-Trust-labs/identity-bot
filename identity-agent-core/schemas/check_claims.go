package schemas

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// CheckClaims refuses a claims block that this schema's own document would
// refuse in a strict verifier, naming the field that fails: a field the schema
// does not declare, a required field missing, a value of the wrong type, one
// outside the allowed values or range, or a date that is not one. It reads the
// attributes block from the published document itself, so it cannot drift from
// what verifiers are given. "d" and "dt" are written by the issuing engine and
// are neither required nor checked here.
func (s *BuiltinSchema) CheckClaims(claims map[string]interface{}) error {
	var doc struct {
		Properties struct {
			A struct {
				OneOf []struct {
					Type       string                     `json:"type"`
					Properties map[string]json.RawMessage `json:"properties"`
					Required   []string                   `json:"required"`
				} `json:"oneOf"`
			} `json:"a"`
		} `json:"properties"`
	}
	if err := json.Unmarshal([]byte(s.JSON), &doc); err != nil {
		return fmt.Errorf("the %s schema cannot be read: %w", s.Name, err)
	}
	var block *struct {
		Type       string                     `json:"type"`
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	for i := range doc.Properties.A.OneOf {
		if doc.Properties.A.OneOf[i].Type == "object" {
			block = &doc.Properties.A.OneOf[i]
		}
	}
	if block == nil {
		return fmt.Errorf("the %s schema has no attributes block", s.Name)
	}
	for _, r := range block.Required {
		if r == "d" || r == "dt" {
			continue
		}
		if _, ok := claims[r]; !ok {
			return fmt.Errorf("%s: %q is required", s.Name, r)
		}
	}
	names := make([]string, 0, len(claims))
	for k := range claims {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		raw, ok := block.Properties[k]
		if !ok {
			return fmt.Errorf("%s: %q is not a field of this schema", s.Name, k)
		}
		if k == "d" || k == "dt" {
			continue
		}
		var def struct {
			Type   string                 `json:"type"`
			Format string                 `json:"format"`
			Enum   []string               `json:"enum"`
			Min    *float64               `json:"minimum"`
			Max    *float64               `json:"maximum"`
			Items  *struct{ Type string } `json:"items"`
		}
		if err := json.Unmarshal(raw, &def); err != nil {
			return fmt.Errorf("%s: %q: its definition cannot be read: %w", s.Name, k, err)
		}
		if err := checkValue(def.Type, def.Format, def.Enum, def.Min, def.Max, claims[k]); err != nil {
			return fmt.Errorf("%s: %q %w", s.Name, k, err)
		}
		if def.Type == "array" && def.Items != nil {
			for i, e := range claims[k].([]interface{}) {
				if err := checkValue(def.Items.Type, "", nil, nil, nil, e); err != nil {
					return fmt.Errorf("%s: %q item %d %w", s.Name, k, i, err)
				}
			}
		}
	}
	return nil
}

func checkValue(typ, format string, enum []string, min, max *float64, v interface{}) error {
	switch typ {
	case "string":
		str, ok := v.(string)
		if !ok {
			return fmt.Errorf("must be a string, not %T", v)
		}
		if format == "date" {
			if _, err := time.Parse("2006-01-02", str); err != nil {
				return fmt.Errorf("must be a date as YYYY-MM-DD, not %q", str)
			}
		}
		if len(enum) > 0 {
			for _, e := range enum {
				if e == str {
					return nil
				}
			}
			return fmt.Errorf("must be one of %v, not %q", enum, str)
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("must be true or false, not %T", v)
		}
	case "integer":
		var f float64
		switch n := v.(type) {
		case int:
			f = float64(n)
		case int64:
			f = float64(n)
		case float64:
			f = n
		case json.Number:
			g, err := n.Float64()
			if err != nil {
				return fmt.Errorf("must be an integer, not %v", v)
			}
			f = g
		default:
			return fmt.Errorf("must be an integer, not %T", v)
		}
		if f != float64(int64(f)) {
			return fmt.Errorf("must be an integer, not %v", v)
		}
		if min != nil && f < *min {
			return fmt.Errorf("must be at least %v, not %v", *min, f)
		}
		if max != nil && f > *max {
			return fmt.Errorf("must be at most %v, not %v", *max, f)
		}
	case "array":
		if _, ok := v.([]interface{}); !ok {
			return fmt.Errorf("must be a list, not %T", v)
		}
	}
	return nil
}
