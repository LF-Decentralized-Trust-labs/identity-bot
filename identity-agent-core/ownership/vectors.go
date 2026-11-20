package ownership

import (
	_ "embed"
	"encoding/json"

	"identity-agent-core/drivers"
)

// vectors are pairs of key logs and what the check makes of each: the file
// another implementation tests itself against. It ships inside this module so
// a Go implementation reads the same file instead of keeping a copy.
//
//go:embed owned-vectors.json
var vectors []byte

// VectorSet is the published set of ownership vectors.
type VectorSet struct {
	About string `json:"about"`
	// Seeds are the 32-byte Ed25519 seeds (RFC 8032), lowercase hex, of every
	// key that signs an event in the cases, by a label. A label ending /0 is
	// the key an identity is founded on, /1 the key its first rotation brings
	// in, and so on.
	Seeds map[string]string `json:"seeds"`
	// Witnesses are the witnesses the logs name, by a label: each one's seed
	// and the non-transferable identifier it gives.
	Witnesses map[string]VectorWitness `json:"witnesses"`
	Cases     []VectorCase             `json:"cases"`
}

// VectorWitness is one witness of the cases.
type VectorWitness struct {
	Seed       string `json:"seed"`
	Identifier string `json:"identifier"`
}

// VectorCase is two logs, what else the verifier holds, and the result.
type VectorCase struct {
	Label string `json:"label"`
	Why   string `json:"why"`
	// Machine is the log of the Identity Agent and Owner the log of the owner
	// identity it is checked against.
	Machine VectorLog `json:"machine"`
	Owner   VectorLog `json:"owner"`
	// OtherLogs are logs of other identifiers the verifier was given.
	OtherLogs []VectorLog `json:"other_logs,omitempty"`
	Expect    Result      `json:"expect"`
}

// VectorLog is a Log as the file writes it.
type VectorLog struct {
	// Messages are the events in order, each the event's JSON followed by its
	// attached controller signatures, as text.
	Messages []string `json:"messages"`
	// Receipts are witness receipts by the SAID of the event receipted.
	Receipts map[string][]VectorReceipt `json:"receipts,omitempty"`
	// Source is "its_witnesses" or "checked_party".
	Source string `json:"source"`
	// Kept are other copies of the log the verifier holds.
	Kept [][]string `json:"kept,omitempty"`
}

// VectorReceipt is one witness's receipt of an event: its identifier and its
// indexed signature over the event's bytes.
type VectorReceipt struct {
	Witness   string `json:"witness"`
	Signature string `json:"signature"`
}

// The two spellings of Source in the file.
const (
	sourceWitnesses    = "its_witnesses"
	sourceCheckedParty = "checked_party"
)

// Log is the log a vector holds, as Check takes it.
func (v VectorLog) Log() Log {
	l := Log{Messages: texts(v.Messages)}
	if v.Source == sourceWitnesses {
		l.Source = FromItsWitnesses
	}
	for said, list := range v.Receipts {
		if l.Receipts == nil {
			l.Receipts = map[string][]drivers.WitnessReceipt{}
		}
		for _, r := range list {
			l.Receipts[said] = append(l.Receipts[said], drivers.WitnessReceipt{WitnessAID: r.Witness, CesrSignature: r.Signature})
		}
	}
	for _, k := range v.Kept {
		l.Kept = append(l.Kept, texts(k))
	}
	return l
}

// Check runs the case through Check.
func (c VectorCase) Check() Result {
	var opt Options
	for _, o := range c.OtherLogs {
		opt.OtherLogs = append(opt.OtherLogs, o.Log())
	}
	return Check(c.Machine.Log(), c.Owner.Log(), opt)
}

func texts(in []string) [][]byte {
	out := make([][]byte, 0, len(in))
	for _, s := range in {
		out = append(out, []byte(s))
	}
	return out
}

// Vectors returns the published vectors.
func Vectors() (*VectorSet, error) {
	var v VectorSet
	if err := json.Unmarshal(vectors, &v); err != nil {
		return nil, err
	}
	return &v, nil
}
