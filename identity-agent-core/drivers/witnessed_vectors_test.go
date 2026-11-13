package drivers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// The cases a page's reader of a witnessed key log is held to
// (packages/login-web/src/witnessed.ts, and login-dart's), run through the
// core's own ReadWitnessedLog and JudgeLinkLog (witnessed_log.go), which are
// product code: nothing here is a rule of its own.
var witnessedVectorsPath = filepath.Join("..", "..", "packages", "login-web", "test-vectors", "seal.json")

type witnessedCase struct {
	Name    string          `json:"name"`
	RID     string          `json:"rid"`
	Answers []WitnessAnswer `json:"answers"`
	Events  *int            `json:"events"`
	Refuse  bool            `json:"refuse"`
	// Proven is a refusal that is the witnesses' proof about the identifier, not the want of a log.
	Proven bool `json:"proven"`
}

func TestAPagesWitnessedLogCasesAreTheCores(t *testing.T) {
	raw, err := os.ReadFile(witnessedVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Witnessed struct {
			Cases []witnessedCase `json:"cases"`
		} `json:"witnessed"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Witnessed.Cases) < 10 {
		t.Fatalf("the shared cases are missing: %d", len(v.Witnessed.Cases))
	}
	for _, c := range v.Witnessed.Cases {
		w, err := ReadWitnessedLog(c.RID, c.Answers)
		switch {
		case c.Refuse && err == nil:
			t.Errorf("%s: taken (%d events), want refused", c.Name, len(w.SAIDs))
		case c.Refuse && c.Proven != errors.Is(err, ErrWitnessesRefuse):
			t.Errorf("%s: refused as %v, want proven=%v", c.Name, err, c.Proven)
		case !c.Refuse && (err != nil || len(w.SAIDs) != *c.Events):
			t.Errorf("%s: got %v %v; want %d", c.Name, w, err, *c.Events)
		}
	}
}

// linkSAIDs reads the events of a log as a link carries it (base64url of a CESR
// stream: each event's JSON, then "-AAB" and its 88-character signature) as
// their SAIDs.
func linkSAIDs(t *testing.T, link string) []string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(link)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for pos := 0; pos < len(b); {
		var n int
		if _, err := fmt.Sscanf(string(b[pos:pos+24]), `{"v":"KERI10JSON%06x_"`, &n); err != nil {
			t.Fatalf("a link's log does not begin an event at %d: %v", pos, err)
		}
		ev, err := keri.ParseEvent(b[pos : pos+n])
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ev.SAID)
		pos += n + 92
	}
	return out
}

func TestALinksLogIsJudgedAgainstItsWitnessesAsThePageJudgesIt(t *testing.T) {
	raw, err := os.ReadFile(witnessedVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Witnessed struct {
			Against []struct {
				Name    string          `json:"name"`
				RID     string          `json:"rid"`
				Link    string          `json:"link_log"`
				Answers []WitnessAnswer `json:"answers"`
				Verdict string          `json:"verdict"`
			} `json:"against_link"`
		} `json:"witnessed"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Witnessed.Against) < 4 {
		t.Fatalf("the shared cases are missing: %d", len(v.Witnessed.Against))
	}
	for _, c := range v.Witnessed.Against {
		got := string(JudgeLinkLog(c.RID, linkSAIDs(t, c.Link), c.Answers))
		if got != c.Verdict {
			t.Errorf("%s: %s, want %s", c.Name, got, c.Verdict)
		}
	}
}
