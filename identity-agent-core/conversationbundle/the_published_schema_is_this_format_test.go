package conversationbundle

import (
	"testing"

	"identity-agent-core/activitylog"
	"identity-agent-core/internal/contractcheck"
)

// The schema in contracts/conversation-bundle is what an export writes and
// what Read accepts. A verifier written in another language is written from
// that file, so a field added here and not there is one it would refuse.
func TestThePublishedSchemaDescribesTheBundle(t *testing.T) {
	s, err := contractcheck.Read("../contracts/conversation-bundle/conversation-bundle.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]any{
		"bundle":                Bundle{},
		"entry":                 Entry{},
		"key_log":               KeyLog{},
		"event":                 Event{},
		"receipt":               Receipt{},
		"registry":              Registry{},
		"credential":            Credential{},
		"owner":                 Owner{},
		"log":                   Log{},
		"stored_row":            activitylog.StoredRow{},
		"log_record":            activitylog.InvocationEvent{},
		"cost":                  activitylog.Cost{},
		"anchor":                Anchor{},
		"anchor_statement":      activitylog.AnchorStatement{},
		"anchored_log":          activitylog.AnchoredLog{},
		"anchored_conversation": activitylog.AnchoredConversation{},
	}
	var faults []string
	for def, v := range held {
		faults = append(faults, s.Matches(def, v)...)
	}
	faults = append(faults, s.Unheld(held)...)
	for _, f := range faults {
		t.Error(f)
	}
}
