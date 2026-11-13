package drivers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// The cases a page's reader of a witnessed key log is held to
// (packages/login-web/src/witnessed.ts, and login-dart's), run through the
// core's own rules: keri.ValidateKEL and ValidateKELFromBytes for the log,
// WitnessingByEvent for its receipts. The page's reader and the core's are two
// implementations of one rule, so a case on which they differ is a bug in one.
//
// What a page does with several witnesses' answers (pool the receipts, take the
// longest log whose every event has its threshold, refuse two receipted logs
// that disagree) is written out here as the page's reader says it, because the
// core takes one log from one place and has no pooling of its own.
var witnessedVectorsPath = filepath.Join("..", "..", "packages", "login-web", "test-vectors", "seal.json")

type witnessedAnswer struct {
	AID string `json:"aid"`
	KEL []struct {
		Raw      string `json:"raw_bytes_b64"`
		Sig      string `json:"cesr_signature"`
		Receipts []struct {
			Witness string `json:"witness"`
			Sig     string `json:"cesr_signature"`
		} `json:"witness_receipts"`
	} `json:"kel"`
}

type witnessedCase struct {
	Name    string            `json:"name"`
	RID     string            `json:"rid"`
	Answers []witnessedAnswer `json:"answers"`
	Events  *int              `json:"events"`
	Refuse  bool              `json:"refuse"`
}

type readLog struct {
	raws [][]byte
	said []string
}

// takenFromWitnesses is what the page's reader takes from the answers, as a count of
// events, or false for a refusal.
func takenFromWitnesses(c witnessedCase) (int, bool) {
	n, _, ok := witnessedSAIDs(c.RID, c.Answers)
	return n, ok
}

func witnessedSAIDs(rid string, answers []witnessedAnswer) (int, []string, bool) {
	receipts := map[string][]WitnessReceipt{}
	var logs []readLog
	for _, a := range answers {
		if a.AID != rid || len(a.KEL) == 0 {
			continue
		}
		in := ValidateKELInput{AID: rid}
		for _, e := range a.KEL {
			raw, err := base64.StdEncoding.DecodeString(e.Raw)
			if err != nil {
				return 0, nil, false
			}
			in.RawEvents = append(in.RawEvents, raw)
			in.CesrSignatures = append(in.CesrSignatures, e.Sig)
		}
		res, err := ValidateKELFromBytes(in)
		if err != nil || len(res.ValidationErrors) != 0 || !res.KelVerified {
			continue
		}
		l := readLog{raws: in.RawEvents}
		for i, e := range a.KEL {
			ev, _ := keri.ParseEvent(in.RawEvents[i])
			l.said = append(l.said, ev.SAID)
			for _, r := range e.Receipts {
				receipts[ev.SAID] = append(receipts[ev.SAID], WitnessReceipt{WitnessAID: r.Witness, CesrSignature: r.Sig})
			}
		}
		logs = append(logs, l)
	}
	if len(logs) == 0 {
		return 0, nil, false
	}
	// A log is a witnessed one when the witnesses in force where its receipted
	// run stops are named and asked for a receipt; events before witnesses were
	// named need none.
	var kept []readLog
	var through []int
	for _, l := range logs {
		rep := WitnessingByEvent(ValidateKELInput{AID: rid, RawEvents: l.raws, Receipts: receipts})
		n, row := 0, EventWitnessing{}
		for _, said := range l.said {
			row = rep[said]
			if !row.Met {
				break
			}
			n++
		}
		if len(row.Designated) > 0 && row.Threshold > 0 {
			kept = append(kept, l)
			through = append(through, n)
		}
	}
	logs = kept
	if len(logs) == 0 {
		return 0, nil, false
	}
	best := 0
	for i := range logs {
		if through[i] > through[best] {
			best = i
		}
	}
	for i := range logs {
		for j := range logs {
			reach := min(through[i], through[j])
			for k := 0; k < reach; k++ {
				if logs[i].said[k] != logs[j].said[k] {
					return 0, nil, false
				}
			}
		}
	}
	if through[best] == 0 {
		return 0, nil, false
	}
	return through[best], logs[best].said[:through[best]], true
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
		n, ok := takenFromWitnesses(c)
		switch {
		case c.Refuse && ok:
			t.Errorf("%s: taken (%d events), want refused", c.Name, n)
		case !c.Refuse && (!ok || n != *c.Events):
			t.Errorf("%s: got %d events, ok=%v; want %d", c.Name, n, ok, *c.Events)
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
				Name    string            `json:"name"`
				RID     string            `json:"rid"`
				Link    string            `json:"link_log"`
				Answers []witnessedAnswer `json:"answers"`
				Verdict string            `json:"verdict"`
			} `json:"against_link"`
		} `json:"witnessed"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Witnessed.Against) < 4 {
		t.Fatalf("the shared cases are missing: %d", len(v.Witnessed.Against))
	}
	prefix := func(long, short []string) bool {
		if len(long) < len(short) {
			return false
		}
		for i := range short {
			if long[i] != short[i] {
				return false
			}
		}
		return true
	}
	for _, c := range v.Witnessed.Against {
		_, w, ok := witnessedSAIDs(c.RID, c.Answers)
		mine := linkSAIDs(t, c.Link)
		got := "none"
		switch {
		case !ok:
		case prefix(mine, w):
			got = "agrees"
		case prefix(w, mine):
			got = "moved_on"
		default:
			got = "apart"
		}
		if got != c.Verdict {
			t.Errorf("%s: %s, want %s", c.Name, got, c.Verdict)
		}
	}
}
