package watcher

import (
	"reflect"
	"testing"
)

// What this watcher has seen must not be readable from another package except
// through the opt-out check, or a new route could answer from it and skip the
// opt-out. Every exported method of the Store and of the Service is walked, and
// what it returns must not carry an observation (observationIn). Only the three
// Disclosable reads, which are the check, may return one.
func TestNoExportedReadReturnsAnObservation(t *testing.T) {
	theCheck := map[string]bool{"Disclosable": true, "DisclosableAll": true, "DisclosableAlerts": true}
	for _, owner := range []reflect.Type{reflect.TypeOf((*Store)(nil)).Elem(), reflect.TypeOf(&Service{})} {
		for i := 0; i < owner.NumMethod(); i++ {
			m := owner.Method(i)
			if !m.IsExported() || (owner.Kind() == reflect.Ptr && theCheck[m.Name]) {
				continue
			}
			for j := 0; j < m.Type.NumOut(); j++ {
				if p := observationIn(m.Type.Out(j)); p != "" {
					t.Errorf("%s.%s is exported and returns %s: another package can read what the watcher saw without the opt-out check",
						owner, m.Name, p)
				}
			}
		}
	}
}

// The walk is only worth something if it fails on the reads it exists to stop.
func TestTheObservationWalkCatchesEachKind(t *testing.T) {
	type result struct {
		Alert        *DuplicityAlert
		FirstContact bool
	}
	for name, typ := range map[string]reflect.Type{
		"a first-seen record":      reflect.TypeOf([]FirstSeenRecord{}),
		"a duplicity alert":        reflect.TypeOf(&DuplicityAlert{}),
		"a per-source outcome":     reflect.TypeOf(map[string]SourceOutcome{}),
		"a first-contact flag":     reflect.TypeOf(struct{ FirstContact bool }{}),
		"an alert inside a result": reflect.TypeOf(&result{}),
	} {
		if observationIn(typ) == "" {
			t.Errorf("the walk does not catch %s", name)
		}
	}
}

// observationIn names the first observation a value of type t carries, or ""
// when it carries none. It looks through pointers, slices, arrays, maps and
// exported struct fields for a first-seen record, a duplicity alert, a
// per-source outcome (whose L1 entry says whether the watcher had seen the
// identity) or a field named FirstContact.
func observationIn(t reflect.Type) string {
	observations := map[reflect.Type]bool{
		reflect.TypeOf(FirstSeenRecord{}): true,
		reflect.TypeOf(DuplicityAlert{}):  true,
		reflect.TypeOf(SourceOutcome{}):   true,
	}
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type) string
	walk = func(t reflect.Type) string {
		for t.Kind() == reflect.Ptr || t.Kind() == reflect.Slice || t.Kind() == reflect.Array || t.Kind() == reflect.Map {
			if t.Kind() == reflect.Map {
				if p := walk(t.Key()); p != "" {
					return p
				}
			}
			t = t.Elem()
		}
		if observations[t] {
			return t.Name()
		}
		if t.Kind() != reflect.Struct || seen[t] {
			return ""
		}
		seen[t] = true
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			if f.Name == "FirstContact" {
				return t.String() + ".FirstContact"
			}
			if p := walk(f.Type); p != "" {
				return t.String() + "." + f.Name + " -> " + p
			}
		}
		return ""
	}
	return walk(t)
}
