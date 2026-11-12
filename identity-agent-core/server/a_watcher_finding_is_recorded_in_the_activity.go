package server

import (
	"fmt"

	"identity-agent-core/permission"
)

// The watcher findings that reach the Activity list. Each is a decision the
// person has to be able to see later, so each is written to the signed log
// when it happens, not only broadcast to whoever is connected at the time.
// Routine findings (first seen, matched what was kept) are not written: they
// would bury these.
//
// The row's capability id is "watcher." plus the event's name.
var watcherFindingsKept = map[string]string{
	"kel_duplicity_detected": "error",  // a fork was proven and the contact was refused
	"kel_watcher_flagged":    "denied", // a watcher's answer did not hold up and was set aside
	"kel_l3_escalation":      "ok",     // a watcher the person trusts disagrees; nothing is proved
}

// recordWatcherFinding writes one Activity row for a watcher finding. The
// contact is the row's correlation id, so every finding about one contact
// is found together. No digest, key or signed event goes in the row: the
// reason names the finding and, for a flagged watcher, how its answer failed.
func (s *CoreServer) recordWatcherFinding(eventType string, payload map[string]interface{}) {
	status, kept := watcherFindingsKept[eventType]
	if !kept || s.ActivityLog == nil {
		return
	}
	aid, _ := payload["aid"].(string)
	var why string
	switch eventType {
	case "kel_watcher_flagged":
		w, _ := payload["watcher"].(string)
		r, _ := payload["why"].(string)
		why = fmt.Sprintf("watcher %s was set aside: %s", w, r)
	default:
		why, _ = payload["reason"].(string)
	}
	s.ActivityLog.RecordGovernanceEvent(permission.CallerContext{
		CorrelationID: aid, Transport: "watcher", Reason: clampWhy(why),
	}, "watcher."+eventType, status)
}
