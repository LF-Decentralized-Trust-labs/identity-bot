package keriengine

import "testing"

// A sequence number is read as KERI writes it. fmt's %x stopped at the first
// character it could not read, so "2zz" read as 2, and it took uppercase and
// leading zeros too.
func TestASequenceNumberHasOneSpelling(t *testing.T) {
	for in, want := range map[string]int{"0": 0, "2": 2, "a": 10, "10": 16} {
		if got, err := hexSN(in); err != nil || got != want {
			t.Errorf("%q read as %d (%v), want %d", in, got, err, want)
		}
	}
	for _, bad := range []interface{}{"2zz", "A", "0a", "02", "", "-1", 2, 2.0} {
		if n, err := hexSN(bad); err == nil {
			t.Errorf("%#v read as %d", bad, n)
		}
	}
}
