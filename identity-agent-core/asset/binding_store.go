package asset

import (
	"errors"
	"slices"
	"time"
)

// ErrBindingKnown is for a joining that is already kept.
var ErrBindingKnown = errors.New("those two identifiers are already joined")

// AddBinding keeps a joining. It fails, keeping nothing, if it cannot be saved.
func (s *Store) AddBinding(b Binding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, have := range s.bindings {
		if have.Record == b.Record && have.New == b.New {
			return ErrBindingKnown
		}
	}
	if b.At.IsZero() {
		b.At = time.Now().UTC()
	}
	s.bindings = append(s.bindings, b)
	if err := s.saveLocked(s.bindingsPath, s.bindings); err != nil {
		s.bindings = s.bindings[:len(s.bindings)-1]
		return err
	}
	return nil
}

// Bindings lists every joining kept.
func (s *Store) Bindings() []Binding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.bindings)
}

// RecordOf is every identifier joined to the record that holds id, id included,
// in a stable order: joinings are read as joining, in either direction, so a
// record that was joined to another (a person's second identifier joined with
// both keys) is one record.
func (s *Store) RecordOf(id string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return recordOf(s.bindings, id)
}

func recordOf(bs []Binding, id string) []string {
	seen := map[string]bool{id: true}
	for grew := true; grew; {
		grew = false
		for _, b := range bs {
			if seen[b.Record] != seen[b.New] {
				seen[b.Record], seen[b.New] = true, true
				grew = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
