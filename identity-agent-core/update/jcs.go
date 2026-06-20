package update

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Canonicalize applies RFC 8785 JSON Canonicalization Scheme (JCS) to raw JSON.
func Canonicalize(raw []byte) ([]byte, error) {
	var v interface{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("jcs: parse: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonicalValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CanonicalizeWithoutField canonicalizes JSON after removing a top-level field.
func CanonicalizeWithoutField(raw []byte, field string) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("jcs: expected object: %w", err)
	}
	delete(obj, field)
	stripped, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return Canonicalize(stripped)
}

func writeCanonicalValue(buf *bytes.Buffer, v interface{}) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		return writeCanonicalNumber(buf, t)
	case string:
		return writeCanonicalString(buf, t)
	case []interface{}:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalValue(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return lexicographicUTF16(keys[i], keys[j]) < 0
		})
		buf.WriteByte('{')
		first := true
		for _, k := range keys {
			if !first {
				buf.WriteByte(',')
			}
			first = false
			if err := writeCanonicalString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonicalValue(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("jcs: unsupported type %T", v)
	}
	return nil
}

func writeCanonicalNumber(buf *bytes.Buffer, n json.Number) error {
	s := string(n)
	if strings.ContainsAny(s, "eE") {
		f, err := n.Float64()
		if err != nil {
			return fmt.Errorf("jcs: number: %w", err)
		}
		buf.WriteString(ecmaScriptNumber(f))
		return nil
	}
	if strings.Contains(s, ".") {
		f, err := n.Float64()
		if err != nil {
			return fmt.Errorf("jcs: number: %w", err)
		}
		buf.WriteString(ecmaScriptNumber(f))
		return nil
	}
	i, err := n.Int64()
	if err != nil {
		f, err2 := n.Float64()
		if err2 != nil {
			return fmt.Errorf("jcs: number: %w", err)
		}
		buf.WriteString(ecmaScriptNumber(f))
		return nil
	}
	buf.WriteString(strconv.FormatInt(i, 10))
	return nil
}

func ecmaScriptNumber(f float64) string {
	if mathIsNaN(f) || mathIsInf(f) {
		return "null"
	}
	s := strconv.FormatFloat(f, 'g', -1, 64)
	if strings.Contains(s, "e") || strings.Contains(s, "E") {
		return s
	}
	if !strings.Contains(s, ".") && !strings.Contains(s, "e") && !strings.Contains(s, "E") {
		if s == "-0" {
			return "0"
		}
		return s
	}
	return s
}

func writeCanonicalString(buf *bytes.Buffer, s string) error {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else if r < 0xd800 || (r > 0xdfff && r <= 0xffff) {
				buf.WriteRune(r)
			} else {
				// Supplementary planes handled via UTF-16 surrogate pairs in source string.
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

// lexicographicUTF16 compares strings per RFC 8785 (UTF-16 code unit order).
func lexicographicUTF16(a, b string) int {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			if ua[i] < ub[i] {
				return -1
			}
			return 1
		}
	}
	if len(ua) == len(ub) {
		return 0
	}
	if len(ua) < len(ub) {
		return -1
	}
	return 1
}

func mathIsNaN(f float64) bool {
	return f != f
}

func mathIsInf(f float64) bool {
	return f > 1e308 || f < -1e308
}