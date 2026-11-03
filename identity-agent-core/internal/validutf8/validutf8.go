// Package validutf8 makes every string in a value valid UTF-8 before the value
// is signed or compared as bytes.
//
// The encoder writes a bad byte as the escape �, which reads back as the
// replacement character and encodes again raw. So a value holding invalid
// UTF-8 does not round-trip, and bytes signed from it do not equal the bytes
// re-encoded from what is read back. Which spelling an encoder gives a bad
// byte is also its own choice and has changed between Go releases. Replacing
// the bad bytes first means no signed byte depends on that choice.
package validutf8

import (
	"fmt"
	"reflect"
	"strings"
)

// Of returns v with each run of invalid UTF-8 in every string replaced by the
// replacement character. Strings are found by reflection, in structs, slices,
// arrays, maps (keys and values), interfaces and the values pointers lead to,
// so a string added later is covered without anyone listing it. Slices, maps
// and pointed-to values are copied, never changed underneath the caller.
// Unexported fields cannot be set and are left as they are.
//
// Two map keys that differ only in their invalid bytes would become one key
// and one of their values would be dropped without a word, so Of refuses that
// with an error. A value that reaches itself through pointers, maps or slices
// has no end to walk, so Of refuses that too. A value shared by two places
// without a loop is fine.
func Of[T any](v T) (T, error) {
	rv := reflect.ValueOf(&v).Elem()
	if err := fix(rv, map[visit]bool{}); err != nil {
		var zero T
		return zero, err
	}
	return v, nil
}

// visit names something reached by address, on the way down only.
type visit struct {
	p uintptr
	n int
	t reflect.Type
}

func enter(v reflect.Value, n int, on map[visit]bool) (visit, error) {
	k := visit{v.Pointer(), n, v.Type()}
	if on[k] {
		return k, fmt.Errorf("validutf8: a value of type %s reaches itself", v.Type())
	}
	on[k] = true
	return k, nil
}

func fix(v reflect.Value, on map[visit]bool) error {
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString(strings.ToValidUTF8(v.String(), "�"))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if err := fix(v.Field(i), on); err != nil {
				return err
			}
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := fix(v.Index(i), on); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if v.Len() == 0 || !v.CanSet() {
			return nil
		}
		k, err := enter(v, v.Len(), on)
		if err != nil {
			return err
		}
		defer delete(on, k)
		cp := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		reflect.Copy(cp, v)
		for i := 0; i < cp.Len(); i++ {
			if err := fix(cp.Index(i), on); err != nil {
				return err
			}
		}
		v.Set(cp)
	case reflect.Map:
		if v.IsNil() || !v.CanSet() {
			return nil
		}
		k0, err := enter(v, 0, on)
		if err != nil {
			return err
		}
		defer delete(on, k0)
		cp := reflect.MakeMapWithSize(v.Type(), v.Len())
		it := v.MapRange()
		for it.Next() {
			k := reflect.New(v.Type().Key()).Elem()
			k.Set(it.Key())
			if err := fix(k, on); err != nil {
				return err
			}
			e := reflect.New(v.Type().Elem()).Elem()
			e.Set(it.Value())
			if err := fix(e, on); err != nil {
				return err
			}
			if cp.MapIndex(k).IsValid() {
				return fmt.Errorf("validutf8: two map keys differ only in their invalid bytes (both become %q)", k.Interface())
			}
			cp.SetMapIndex(k, e)
		}
		v.Set(cp)
	case reflect.Interface:
		if v.IsNil() || !v.CanSet() {
			return nil
		}
		c := reflect.New(v.Elem().Type()).Elem()
		c.Set(v.Elem())
		if err := fix(c, on); err != nil {
			return err
		}
		v.Set(c)
	case reflect.Ptr:
		if v.IsNil() || !v.CanSet() {
			return nil
		}
		k, err := enter(v, 0, on)
		if err != nil {
			return err
		}
		defer delete(on, k)
		cp := reflect.New(v.Type().Elem())
		cp.Elem().Set(v.Elem())
		if err := fix(cp.Elem(), on); err != nil {
			return err
		}
		v.Set(cp)
	}
	return nil
}
