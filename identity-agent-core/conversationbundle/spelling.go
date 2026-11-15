package conversationbundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// A bundle is read from one spelling of its container. Go's decoder, and
// others', are lenient in ways that let two readers see two bundles in one
// file: a key written twice (Go keeps the last, another parser the first, so a
// reader in another language checks a different "head" than this one) and a key
// in another case ("Head" for "head", which Go accepts and a stricter parser
// treats as a different, unknown key). Neither changes a byte anything proves,
// so neither would be noticed by the checks on the entries. Read refuses both:
// every key is written once, exactly as the schema spells it.

// checkSpelling is nil when data has no object with a key written twice, and no
// key of a field spelled other than exactly as v's type writes it.
func checkSpelling(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tree, err := readOnce(dec, "")
	if err != nil {
		return err
	}
	return checkKeys(tree, reflect.TypeOf(v), "")
}

// readOnce reads one JSON value into a tree, failing on a repeated key. A key is
// repeated when it matches another of the same object exactly or ignoring case,
// since Go would fold the two into one field.
func readOnce(dec *json.Decoder, at string) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	switch d {
	case '{':
		obj := map[string]any{}
		seen := map[string]string{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			k, _ := kt.(string)
			if first, dup := seen[strings.ToLower(k)]; dup {
				if first == k {
					return nil, fmt.Errorf("%s: the key %q is written more than once", where(at), k)
				}
				return nil, fmt.Errorf("%s: the keys %q and %q are one field spelled twice", where(at), first, k)
			}
			seen[strings.ToLower(k)] = k
			child, err := readOnce(dec, at+"/"+k)
			if err != nil {
				return nil, err
			}
			obj[k] = child
		}
		if _, err := dec.Token(); err != nil { // '}'
			return nil, err
		}
		return obj, nil
	case '[':
		var arr []any
		for i := 0; dec.More(); i++ {
			child, err := readOnce(dec, fmt.Sprintf("%s/%d", at, i))
			if err != nil {
				return nil, err
			}
			arr = append(arr, child)
		}
		if _, err := dec.Token(); err != nil { // ']'
			return nil, err
		}
		return arr, nil
	}
	return nil, errors.New("unexpected JSON")
}

func where(at string) string {
	if at == "" {
		return "the bundle"
	}
	return at
}

// checkKeys walks tree beside the type it is decoded into, and fails on a key
// that is not exactly the name of one of that struct's fields.
func checkKeys(tree any, t reflect.Type, at string) error {
	for t != nil && (t.Kind() == reflect.Pointer) {
		t = t.Elem()
	}
	if t == nil {
		return nil
	}
	switch node := tree.(type) {
	case map[string]any:
		if t.Kind() != reflect.Struct {
			return nil // a free-form map: its keys are data
		}
		fields := jsonFields(t)
		for k, child := range node {
			ft, known := fields[k]
			if !known {
				for name := range fields {
					if strings.EqualFold(name, k) {
						return fmt.Errorf("%s: the key %q is spelled %q", where(at), k, name)
					}
				}
				continue // an unknown field is DisallowUnknownFields' to refuse
			}
			if err := checkKeys(child, ft, at+"/"+k); err != nil {
				return err
			}
		}
	case []any:
		if t.Kind() != reflect.Slice && t.Kind() != reflect.Array {
			return nil
		}
		for i, child := range node {
			if err := checkKeys(child, t.Elem(), fmt.Sprintf("%s/%d", at, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// jsonFields is the JSON name and type of each field of struct type t.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		switch {
		case tag == "-":
			continue
		case f.Anonymous && name == "":
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				for k, v := range jsonFields(ft) {
					out[k] = v
				}
				continue
			}
		case !f.IsExported():
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
	return out
}
