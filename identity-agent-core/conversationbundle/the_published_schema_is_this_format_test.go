package conversationbundle

import (
	"bytes"
	"encoding/json"
	"testing"

	"identity-agent-core/internal/contractcheck"
	"identity-agent-core/sandbox"
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
		"stored_row":            sandbox.StoredRow{},
		"log_record":            sandbox.InvocationEvent{},
		"cost":                  sandbox.Cost{},
		"anchor":                Anchor{},
		"anchor_statement":      AnchorStatement{},
		"anchored_log":          AnchoredLog{},
		"anchored_conversation": AnchoredConversation{},
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

// A bundle as Build writes it reads back through Read unchanged: nothing an
// export writes is a field the format does not have.
func TestABuiltBundleReadsBack(t *testing.T) {
	b, err := build(t, newStore(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Read(raw)
	if err != nil {
		t.Fatalf("an exported bundle does not read back: %v", err)
	}
	again, _ := json.Marshal(got)
	if !bytes.Equal(raw, again) {
		t.Fatal("an exported bundle changed on reading back")
	}
}
