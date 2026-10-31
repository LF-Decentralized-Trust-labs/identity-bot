// Package strictjson reads a JSON document into a Go value only if every
// reader of it would read the same thing.
//
// encoding/json is lenient in ways another language's parser is not, and a
// signed document read two ways is signed for neither:
//
//   - it matches an object key to a struct field ignoring case, so
//     {"nonce":"n","Nonce":"x"} reads its nonce as "x" here and as "n" in a
//     parser that matches names exactly;
//   - of a repeated key it keeps the last, where some parsers keep the first;
//   - it replaces invalid UTF-8, and an escaped surrogate with no partner, with
//     U+FFFD, so two different keys can arrive as one;
//   - it reads an unknown field by dropping it.
//
// Decode refuses all four, and refuses a whole number written any way but
// one (1.0, 1e0, -0) or too large to be exact in a 64-bit float, so a reader
// in JavaScript reads it as the same number. What it accepts, it then reads
// with encoding/json.
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxExactInt is the largest whole number a 64-bit float holds exactly.
const maxExactInt = 1<<53 - 1

var wholeNumber = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// Decode reads data into v, which must be a pointer, by the rules above.
func Decode(data []byte, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("strictjson: Decode needs a non-nil pointer")
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("the document is not valid UTF-8")
	}
	if err := checkEscapes(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	w := walker{dec: dec}
	if err := w.value(rv.Type().Elem(), "the document", true); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("the document continues after its value")
	}
	return json.Unmarshal(data, v)
}

type walker struct{ dec *json.Decoder }

func (w walker) value(t reflect.Type, at string, top bool) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	tok, err := w.dec.Token()
	if err != nil {
		return fmt.Errorf("%s is not JSON: %w", at, err)
	}
	if top && t.Kind() == reflect.Struct && tok != json.Delim('{') {
		return fmt.Errorf("%s must be an object", at)
	}
	switch tok := tok.(type) {
	case json.Delim:
		switch tok {
		case '{':
			return w.object(t, at)
		case '[':
			elem := reflect.TypeOf((*any)(nil)).Elem()
			if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
				elem = t.Elem()
			}
			for i := 0; w.dec.More(); i++ {
				if err := w.value(elem, fmt.Sprintf("%s[%d]", at, i), false); err != nil {
					return err
				}
			}
			_, err := w.dec.Token() // ]
			return err
		}
	case json.Number:
		switch t.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			s := tok.String()
			if !wholeNumber.MatchString(s) || s == "-0" {
				return fmt.Errorf("%s must be a whole number written plainly, not %s", at, s)
			}
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil || n > maxExactInt || n < -maxExactInt {
				return fmt.Errorf("%s is too large to be read exactly everywhere", at)
			}
		}
	}
	return nil
}

func (w walker) object(t reflect.Type, at string) error {
	var fields map[string]reflect.Type
	elem := reflect.TypeOf((*any)(nil)).Elem()
	switch t.Kind() {
	case reflect.Struct:
		fields = fieldsOf(t)
	case reflect.Map:
		elem = t.Elem()
	}
	seen := map[string]bool{}
	for w.dec.More() {
		tok, err := w.dec.Token()
		if err != nil {
			return fmt.Errorf("%s is not JSON: %w", at, err)
		}
		key, _ := tok.(string)
		if seen[key] {
			return fmt.Errorf("%s names %q twice", at, key)
		}
		seen[key] = true
		vt := elem
		if fields != nil {
			ft, ok := fields[key]
			if !ok {
				return fmt.Errorf("%s has a field %q, which is not one of its fields", at, key)
			}
			vt = ft
		}
		if err := w.value(vt, at+"."+key, false); err != nil {
			return err
		}
	}
	_, err := w.dec.Token() // }
	return err
}

// fieldsOf is each field encoding/json reads into t, under its exact name.
func fieldsOf(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := f.Name
		if tag, ok := f.Tag.Lookup("json"); ok {
			if tag == "-" {
				continue
			}
			if n, _, _ := strings.Cut(tag, ","); n != "" {
				name = n
			}
		}
		out[name] = f.Type
	}
	return out
}

// checkEscapes refuses an escaped surrogate that is not half of a pair. The
// decoder would read it as U+FFFD, so two different strings would arrive as
// the same one.
func checkEscapes(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 < len(data) && data[i+1] == 'u' {
				u, ok := hex4(data, i+2)
				switch {
				case !ok:
				case u >= 0xD800 && u <= 0xDBFF:
					lo, ok := uint16(0), false
					if i+7 < len(data) && data[i+6] == '\\' && data[i+7] == 'u' {
						lo, ok = hex4(data, i+8)
					}
					if !ok || lo < 0xDC00 || lo > 0xDFFF {
						return fmt.Errorf("the document has half of a surrogate pair, which is not text")
					}
					i += 11
					continue
				case u >= 0xDC00 && u <= 0xDFFF:
					return fmt.Errorf("the document has half of a surrogate pair, which is not text")
				}
			}
			i++ // the escaped character
		}
	}
	return nil
}

func hex4(data []byte, at int) (uint16, bool) {
	if at+4 > len(data) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(data[at:at+4]), 16, 16)
	return uint16(n), err == nil
}
