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
// Two map keys that differ only in their invalid bytes become one key; the
// later one in iteration order wins, so such a map should not be relied on to
// keep both.
func Of[T any](v T) T {
	rv := reflect.ValueOf(&v).Elem()
	fix(rv)
	return v
}

func fix(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString(strings.ToValidUTF8(v.String(), "�"))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			fix(v.Field(i))
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			fix(v.Index(i))
		}
	case reflect.Slice:
		if v.Len() == 0 || !v.CanSet() {
			return
		}
		cp := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		reflect.Copy(cp, v)
		for i := 0; i < cp.Len(); i++ {
			fix(cp.Index(i))
		}
		v.Set(cp)
	case reflect.Map:
		if v.IsNil() || !v.CanSet() {
			return
		}
		cp := reflect.MakeMapWithSize(v.Type(), v.Len())
		it := v.MapRange()
		for it.Next() {
			k := reflect.New(v.Type().Key()).Elem()
			k.Set(it.Key())
			fix(k)
			e := reflect.New(v.Type().Elem()).Elem()
			e.Set(it.Value())
			fix(e)
			cp.SetMapIndex(k, e)
		}
		v.Set(cp)
	case reflect.Interface:
		if v.IsNil() || !v.CanSet() {
			return
		}
		c := reflect.New(v.Elem().Type()).Elem()
		c.Set(v.Elem())
		fix(c)
		v.Set(c)
	case reflect.Ptr:
		if v.IsNil() || !v.CanSet() {
			return
		}
		cp := reflect.New(v.Type().Elem())
		cp.Elem().Set(v.Elem())
		fix(cp.Elem())
		v.Set(cp)
	}
}
