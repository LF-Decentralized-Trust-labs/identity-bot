package server

import (
	"encoding/json"
	"testing"
	"time"

	"identity-agent-core/watcher"
)

// A screen is shown what an alert rests on: for a proven duplicity the two signed
// events, for a flagged watcher why its answer was set aside. Evidence that is not
// JSON is left out rather than sent as text a screen would have to guess at.
//
// Fails when alertJSON drops the evidence, so the owner sees a refusal with
// nothing behind it.
func TestAnAlertCarriesTheEvidenceItRestsOn(t *testing.T) {
	ev := watcher.Evidence{Kind: "duplicity", SequenceNum: 2, HeldMessage: "AAAA", RivalMessage: "BBBB", Watcher: "https://w.example"}
	b, _ := json.Marshal(ev)
	got := alertJSON(watcher.DuplicityAlert{ID: 1, AID: "EA", SequenceNum: 2, DetectedAt: time.Now(), Evidence: string(b)})
	out, _ := json.Marshal(got)
	var back struct {
		Kind     string           `json:"kind"`
		Evidence watcher.Evidence `json:"evidence"`
	}
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if back.Kind != watcher.AlertKindDuplicity || back.Evidence.HeldMessage != "AAAA" || back.Evidence.RivalMessage != "BBBB" {
		t.Fatalf("%s", out)
	}
	none := alertJSON(watcher.DuplicityAlert{ID: 2, AID: "EA", Evidence: "not json"})
	if none.Evidence != nil {
		t.Fatalf("evidence that is not JSON was sent: %s", none.Evidence)
	}
	flag := alertJSON(watcher.DuplicityAlert{ID: 3, AID: "EA", Kind: watcher.AlertKindWatcher, SourceURL: "https://w.example"})
	if flag.Kind != watcher.AlertKindWatcher || flag.SourceURL == "" {
		t.Fatalf("%+v", flag)
	}
}
