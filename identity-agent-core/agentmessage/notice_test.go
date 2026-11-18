package agentmessage

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

// The codes the published schema lists are the codes this package gives words
// to, and the schema says the same words for each: a reader written from the
// schema shows a person what this package would.
func TestTheSchemaListsEveryNoticeCodeWithItsWords(t *testing.T) {
	raw, err := os.ReadFile("../contracts/agent-message/agent-message.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Defs map[string]struct {
			Properties map[string]struct {
				Enum        []string `json:"enum"`
				Description string   `json:"description"`
			} `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	code := s.Defs["notice"].Properties["code"]
	var ours []string
	for c := range noticeWords {
		ours = append(ours, c)
	}
	listed := append([]string(nil), code.Enum...)
	sort.Strings(ours)
	sort.Strings(listed)
	if strings.Join(ours, ",") != strings.Join(listed, ",") {
		t.Fatalf("the schema lists %v and this package gives words to %v", listed, ours)
	}
	for c, w := range noticeWords {
		if !strings.Contains(code.Description, c+":") || !strings.Contains(code.Description, w) {
			t.Errorf("the schema does not give %s its words %q", c, w)
		}
	}
}
