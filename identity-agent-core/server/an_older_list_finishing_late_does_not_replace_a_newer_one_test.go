package server

import (
	"testing"
	"time"

	"identity-agent-core/measurementlist"
)

func TestAnOlderListFinishingLateDoesNotReplaceANewerOne(t *testing.T) {
	m := &measurementLists{}
	now := time.Now()
	m.stage(&measurementlist.List{Sequence: 6}, now)
	m.stage(&measurementlist.List{Sequence: 5}, now.Add(time.Second))
	if m.staged.Sequence != 6 {
		t.Fatalf("staged sequence %d, want 6: an older list replaced a newer one", m.staged.Sequence)
	}
	m.stage(&measurementlist.List{Sequence: 7}, now.Add(2*time.Second))
	if m.staged.Sequence != 7 {
		t.Fatalf("staged sequence %d, want 7", m.staged.Sequence)
	}
}
