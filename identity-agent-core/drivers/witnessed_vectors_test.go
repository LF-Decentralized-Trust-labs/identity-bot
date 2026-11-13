package drivers

import (
	"encoding/base64"
	"encoding/json"
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

type witnessedCase struct {
	Name    string `json:"name"`
	RID     string `json:"rid"`
	Answers []struct {
		AID string `json:"aid"`
		KEL []struct {
			Raw      string `json:"raw_bytes_b64"`
			Sig      string `json:"cesr_signature"`
			Receipts []struct {
				Witness string `json:"witness"`
				Sig     string `json:"cesr_signature"`
			} `json:"witness_receipts"`
		} `json:"kel"`
	} `json:"answers"`
	Events *int `json:"events"`
	Refuse bool `json:"refuse"`
}

type readLog struct {
	raws [][]byte
	said []string
}

// takenFromWitnesses is what the page's reader takes from the answers, as a count of
// events, or false for a refusal.
func takenFromWitnesses(c witnessedCase) (int, bool) {
	receipts := map[string][]WitnessReceipt{}
	var logs []readLog
	for _, a := range c.Answers {
		if a.AID != c.RID || len(a.KEL) == 0 {
			continue
		}
		in := ValidateKELInput{AID: c.RID}
		for _, e := range a.KEL {
			raw, err := base64.StdEncoding.DecodeString(e.Raw)
			if err != nil {
				return 0, false
			}
			in.RawEvents = append(in.RawEvents, raw)
			in.CesrSignatures = append(in.CesrSignatures, e.Sig)
		}
		res, err := ValidateKELFromBytes(in)
		if err != nil || len(res.ValidationErrors) != 0 || !res.KelVerified {
			continue
		}
		first, _ := keri.ParseEvent(in.RawEvents[0])
		if len(first.Witnesses) == 0 || !first.HasTOAD || first.TOAD == 0 {
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
		return 0, false
	}
	through := make([]int, len(logs))
	best := 0
	for i, l := range logs {
		rep := WitnessingByEvent(ValidateKELInput{AID: c.RID, RawEvents: l.raws, Receipts: receipts})
		for _, said := range l.said {
			if !rep[said].Met {
				break
			}
			through[i]++
		}
		if through[i] > through[best] {
			best = i
		}
	}
	for i := range logs {
		for j := range logs {
			reach := min(through[i], through[j])
			for k := 0; k < reach; k++ {
				if logs[i].said[k] != logs[j].said[k] {
					return 0, false
				}
			}
		}
	}
	if through[best] == 0 {
		return 0, false
	}
	return through[best], true
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
