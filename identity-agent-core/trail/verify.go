package trail

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"identity-agent-core/agentmessage"
)

// Report is what an offline check found.
type Report struct {
	Verified bool
	Faults   []string
	Head     string
}

func (r *Report) fault(format string, a ...any) {
	r.Faults = append(r.Faults, fmt.Sprintf(format, a...))
}

// Read parses an exported trail, refusing a field it does not know: a trail
// carries no words, so there is nowhere in it for any to be.
func Read(raw []byte) ([]Entry, error) {
	var es []Entry
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&es); err != nil {
		return nil, err
	}
	return es, nil
}

// Verify checks an exported trail with nothing but the trail: the chain, and
// every entry's author signature. It does so alike for a committed entry, a
// not-kept entry and a refusal, since all three keep their fingerprint and
// their signature and none keeps words.
func Verify(es []Entry) Report {
	var r Report
	var prev, conv, agent string
	versions := make([]int, len(es))
	for i, e := range es {
		versions[i] = e.Statement.FingerprintVersion
	}
	if err := agentmessage.CheckVersionOrder(versions); err != nil {
		r.fault("%v", err)
	}
	for i, e := range es {
		at := fmt.Sprintf("entry %d", i+1)
		if i == 0 {
			conv, agent = e.Statement.Conversation, e.Statement.Agent
		}
		if e.Seq != i+1 || e.ID != EntryID(i+1) {
			r.fault("%s: out of order (seq %d, id %q)", at, e.Seq, e.ID)
		}
		if e.Prev != prev {
			r.fault("%s: it does not follow the entry before it", at)
		}
		if e.Statement.Conversation != conv {
			r.fault("%s: it belongs to another conversation", at)
		}
		if e.Statement.Agent != agent {
			r.fault("%s: it names another Identity Agent", at)
		}
		if err := agentmessage.VerifyPerson(e.Statement, e.Verkey, e.Signature); err != nil {
			r.fault("%s: %v", at, err)
		}
		for _, v := range []string{e.Refusal, e.Recorded, e.CiphertextHash} {
			if strings.ContainsAny(v, "\r\n") {
				r.fault("%s: a field holds a line break", at)
			}
		}
		if _, err := time.Parse(time.RFC3339, e.Recorded); err != nil {
			r.fault("%s: its time is not RFC 3339", at)
		}
		if e.CiphertextHash != "" && e.CiphertextHash != e.Statement.Fingerprint {
			r.fault("%s: its ciphertext hash is not the statement's fingerprint", at)
		}
		switch {
		case e.Refusal != "" && e.Outcome != nil:
			r.fault("%s: a refusal has no outcome", at)
		case e.Outcome != nil && e.Outcome.State != Committed && e.Outcome.State != NotKept:
			r.fault("%s: %q is not an outcome", at, e.Outcome.State)
		case e.Outcome != nil && e.Outcome.State == NotKept && e.Outcome.Reason == "":
			r.fault("%s: a not-kept entry gives its reason", at)
		}
		prev = e.ChainHash()
	}
	r.Head = prev
	r.Verified = len(r.Faults) == 0
	return r
}

// Kept is the words and salt an app exports beside an entry.
type Kept struct {
	Salt  []byte
	Words []byte
}

// VerifyWords is Verify and then, for every committed entry, the check that
// the words and salt the app exported are the ones its fingerprint is of. A
// committed entry with no words, or words for an entry that was not kept, is a
// fault. A not-kept entry and a refusal are checked without words.
func VerifyWords(es []Entry, words map[string]Kept) Report {
	r := Verify(es)
	for _, e := range es {
		k, has := words[e.ID]
		switch e.State() {
		case Committed:
			if !has {
				r.fault("%s: committed, but its words are missing", e.ID)
				continue
			}
			if err := agentmessage.CheckFingerprint(e.Statement.FingerprintVersion, k.Salt, k.Words, e.Statement.Fingerprint, false); err != nil {
				r.fault("%s: %v", e.ID, err)
			}
		default:
			if has {
				r.fault("%s: it is %s, so no words are expected for it", e.ID, e.State())
			}
		}
	}
	r.Verified = len(r.Faults) == 0
	return r
}
