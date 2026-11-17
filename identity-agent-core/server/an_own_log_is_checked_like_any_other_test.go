package server

import (
	"context"
	"testing"

	"identity-agent-core/drivers/signedlog"
	"identity-agent-core/watcher"
)

// This agent's own log is handed to the watcher as the bytes and signatures it
// was kept with, with no parsed fields beside them (ownLogForVerification). It
// is placed and digested from those bytes, so it is a log like any other, not
// one with an "unreadable sequence number".
//
// Fails when the watcher places a log from the fields served beside its bytes.
func TestAnOwnLogWithOnlyItsBytesIsCheckedNotRefusedAsUnreadable(t *testing.T) {
	log := signedlog.Incept(t, signedlog.NewKeys(t, 3)).Interact("one").Interact("two")
	s := watcherAgent(t, "EOther", 1, "Ed")
	res := s.runWatcherOnKel(context.Background(), log.AID, log.Records(), watcher.SourceOOBI, "https://x.example/oobi", nil)
	if res == nil || res.Stopped() || res.OverallOutcome == "unreadable" || res.SequenceNum != log.Len()-1 {
		t.Fatalf("an own log with only its bytes was not checked as the log it is: %+v", res)
	}
}
