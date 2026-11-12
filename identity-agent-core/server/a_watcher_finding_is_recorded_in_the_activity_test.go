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
		{"kel_duplicity_detected", map[string]interface{}{"aid": "ECONTACT", "seq": 3, "reason": "two histories"}, "error", "two histories"},
		{"kel_l3_escalation", map[string]interface{}{"aid": "ECONTACT", "seq": 3, "reason": "the hosted watcher disagrees"}, "ok", "the hosted watcher disagrees"},
		{"kel_watcher_flagged", map[string]interface{}{"aid": "ECONTACT", "seq": 3, "watcher": "https://w.example", "why": "signature check failed"}, "denied", "watcher https://w.example was set aside: signature check failed"},
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
