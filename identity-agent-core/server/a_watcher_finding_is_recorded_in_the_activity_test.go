package server

import (
	"testing"

	"identity-agent-core/activitylog"
)

func TestAWatcherFindingIsRecordedInTheActivity(t *testing.T) {
	cases := []struct {
		event   string
		payload map[string]interface{}
		status  string
		reason  string
	}{
		{"kel_duplicity_detected", map[string]interface{}{"aid": "ECONTACT", "seq": 3, "reason": "two histories"}, "error", "two histories (event 3)"},
		{"kel_l3_escalation", map[string]interface{}{"aid": "ECONTACT", "seq": 3, "reason": "the standing watcher disagrees with this Identity Agent's record"}, "escalated", "the standing watcher disagrees with this Identity Agent's record (event 3)"},
		{"kel_watcher_flagged", map[string]interface{}{"aid": "ECONTACT", "seq": 3, "watcher": "https://w.example", "why": "signature check failed"}, "denied", "watcher https://w.example was set aside: signature check failed (event 3)"},
	}
	for _, c := range cases {
		t.Run(c.event, func(t *testing.T) {
			s := &CoreServer{DataDir: t.TempDir()}
			s.logForTest(t, s.DataDir)
			s.recordWatcherFinding(c.event, c.payload)
			rows := logged(t, s, "watcher."+c.event, "ECONTACT")
			if len(rows) != 1 {
				t.Fatalf("want one Activity row for %s, got %d", c.event, len(rows))
			}
			if rows[0].ResultStatus != c.status || rows[0].Reason != c.reason {
				t.Fatalf("row = %q / %q, want %q / %q", rows[0].ResultStatus, rows[0].Reason, c.status, c.reason)
			}
		})
	}
}

func TestARoutineWatcherEventIsNotRecorded(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	l := s.logForTest(t, s.DataDir)
	s.recordWatcherFinding("kel_first_contact_confirmed", map[string]interface{}{"aid": "ECONTACT"})
	s.recordWatcherFinding("kel_verification", map[string]interface{}{"aid": "ECONTACT"})
	if rows, _ := l.QueryInvocationEvents(activitylog.InvocationEventFilter{}); len(rows) != 0 {
		t.Fatalf("a routine event wrote %d rows", len(rows))
	}
}

func TestWithNoActivityLogAFindingIsStillOnlyBroadcast(t *testing.T) {
	(&CoreServer{}).recordWatcherFinding("kel_duplicity_detected", map[string]interface{}{"aid": "E"})
}

// The same finding, met again on a later check of the same contact, is one row;
// the same kind of finding at another place in the log is a new one.
func TestTheSameFindingMetAgainIsOneActivityRow(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	s.logForTest(t, s.DataDir)
	for _, ev := range []string{"kel_l3_escalation", "kel_watcher_flagged", "kel_duplicity_detected"} {
		p := map[string]interface{}{"aid": "ECONTACT", "seq": 3, "reason": "r", "watcher": "https://w", "why": "y"}
		s.recordWatcherFinding(ev, p)
		s.recordWatcherFinding(ev, p)
		if n := len(logged(t, s, "watcher."+ev, "ECONTACT")); n != 1 {
			t.Fatalf("%s: a repeated finding wrote %d rows, want 1", ev, n)
		}
		p["seq"] = 4
		s.recordWatcherFinding(ev, p)
		if n := len(logged(t, s, "watcher."+ev, "ECONTACT")); n != 2 {
			t.Fatalf("%s: a finding at another place wrote %d rows in all, want 2", ev, n)
		}
	}
}

// New() hands the watcher the function that writes the Activity row. Calling
// recordWatcherFinding directly cannot show that line is there.
func TestTheWatcherServiceMadeByNewRecordsItsFindings(t *testing.T) {
	s, err := New(Config{DataDir: t.TempDir(), Port: 0, EntityType: "individual"})
	if err != nil {
		t.Skipf("server unavailable: %v", err)
	}
	defer s.Stop()
	if s.ActivityLog == nil {
		t.Fatal("New() made no Activity log")
	}
	s.WatcherService.OnEvent("kel_l3_escalation", map[string]interface{}{
		"aid": "ECONTACT", "seq": 3, "reason": "the standing watcher disagrees with this Identity Agent's record"})
	rows := logged(t, s, "watcher.kel_l3_escalation", "ECONTACT")
	if len(rows) != 1 || rows[0].ResultStatus != "escalated" {
		t.Fatalf("a finding raised through the service New() built wrote %d rows %+v, want one escalated", len(rows), rows)
	}
}
