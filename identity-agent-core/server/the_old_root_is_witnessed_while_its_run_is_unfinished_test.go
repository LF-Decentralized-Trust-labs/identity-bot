package server

import (
	"os"
	"path/filepath"
	"testing"
)

// The identity record moves to the new root partway through a break-glass run
// and the old root's root map entry is written at its end. In between, a
// witnessing pass must not drop the old root's job.
func TestTheOldRootsJobSurvivesTheRunThatIsMovingOnFromIt(t *testing.T) {
	const oldRoot, newRoot = "EOldRoot", "ENewRoot"
	s := &CoreServer{DataDir: t.TempDir()}
	runs := filepath.Join(s.DataDir, "root_aid_runs")
	if err := os.MkdirAll(runs, 0o700); err != nil {
		t.Fatal(err)
	}
	run := `{"old_root_aid":"` + oldRoot + `","new_root_aid":"` + newRoot + `"}`
	if err := os.WriteFile(filepath.Join(runs, oldRoot+".json"), []byte(run), 0o600); err != nil {
		t.Fatal(err)
	}
	s.witnessing.witnessJobs = map[string]witnessJob{oldRoot: {owner: oldRoot}, "EGone": {owner: "EGone"}}

	s.dropJobsOfOtherIdentities(newRoot) // the record has moved; no map entry yet

	if _, ok := s.witnessing.witnessJobs[oldRoot]; !ok {
		t.Fatal("the job of the old root of an unfinished run was dropped")
	}
	if _, ok := s.witnessing.witnessJobs["EGone"]; ok {
		t.Fatal("the job of an identity in no run was kept")
	}
}
