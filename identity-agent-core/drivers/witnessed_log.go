package drivers

import (
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf8"

	keri "github.com/grapeid/keri-go"
)

// The log a relay identifier's witnesses together vouch for: what a page's
// reader (packages/login-web/src/witnessed.ts, and login-dart's) takes from the
// answers of several witnesses, written once here in the core's own terms so the
// shared cases (packages/login-web/test-vectors/seal.json, `witnessed`) hold the
// page's readers to the core's rules, not to a second copy of them in a test.
//
// Each answer is read as a key log, the receipts of every answer that reads are
// pooled, and the log taken is the longest one whose every event has its
// threshold of receipts, counted by WitnessingByEvent with these rules:
//
//   - an answer that is for another identifier, is empty or over
//     MaxWitnessedLogEvents events, has bytes that are not in one spelling of
//     base64 or not UTF-8, or whose log keri-go does not take (including a witness
//     list a rotation changes against its rules: a cut of a witness not in the
//     list, an add of one already in it) counts for nothing, and is no error for the
//     others;
//   - a receipt counts only as an indexed signature over the event's bytes (the one
//     keripy makes), at the witness's own place in the list in force; the earlier
//     unindexed 0B signature over the event's SAID is not counted;
//   - a log is a witnessed one when the witnesses in force where its receipted run
//     stops are named and asked for a receipt, so the events before witnesses were
//     named need none;
//   - two such logs that both reach a place must hold the same event there, or the
//     witnesses receipted two histories (ErrWitnessesRefuse), which is proof, not
//     absence;
//   - a log with a rotation that leaves an identifier that had witnesses with none
//     (ErrWitnessesRefuse) is refused whole, for the same reason.

// MaxWitnessedLogEvents is the most events of one answer a reader takes.
const MaxWitnessedLogEvents = 256

// ErrWitnessesRefuse is a refusal that is a proof about the identifier, not the
// want of an answer: the witnesses receipted two histories, or an owner's own
// signed rotation cut every witness it had. A link for it is refused, not taken
// on its minimum.
var ErrWitnessesRefuse = errors.New("the witnesses' key log is refused")

// ErrNoWitnessedLog is the want of a log to take: none read, none named witnesses,
// or none has an event with its threshold of receipts.
var ErrNoWitnessedLog = errors.New("the witnesses gave no key log a page can take")

// WitnessAnswer is a witness's answer to GET /witness/kel/{rid}.
type WitnessAnswer struct {
	AID string               `json:"aid"`
	KEL []WitnessAnswerEvent `json:"kel"`
}

// WitnessAnswerEvent is one entry of an answer: the event's bytes, the
// controller's signature, and this witness's own receipt when it has one.
type WitnessAnswerEvent struct {
	Raw      string `json:"raw_bytes_b64"`
	Sig      string `json:"cesr_signature"`
	Receipts []struct {
		Witness string `json:"witness"`
		Sig     string `json:"cesr_signature"`
	} `json:"witness_receipts"`
}

// WitnessedLog is the log the witnesses vouch for, as far as it has its
// threshold of receipts.
type WitnessedLog struct {
	// SAIDs of its events, in order.
	SAIDs []string
}

type readWitnessedAnswer struct {
	raws [][]byte
	said []string
}

// ReadWitnessedLog takes from answers (those of the witnesses a relay identifier
// names, for rid) the log they together vouch for, as above: ErrNoWitnessedLog
// when there is none, ErrWitnessesRefuse when they prove it wrong.
func ReadWitnessedLog(rid string, answers []WitnessAnswer) (*WitnessedLog, error) {
	receipts := map[string][]WitnessReceipt{}
	var logs []readWitnessedAnswer
	for _, a := range answers {
		if a.AID != rid || len(a.KEL) == 0 || len(a.KEL) > MaxWitnessedLogEvents {
			continue
		}
		in := ValidateKELInput{AID: rid}
		readable := true
		for _, e := range a.KEL {
			raw, err := base64.StdEncoding.Strict().DecodeString(e.Raw)
			// Strict still skips a newline; the page readers refuse any byte outside the alphabet.
			if err != nil || strings.ContainsAny(e.Raw, "\r\n") || len(e.Sig) != 88 || !utf8.Valid(raw) {
				readable = false
				break
			}
			in.RawEvents = append(in.RawEvents, raw)
			in.CesrSignatures = append(in.CesrSignatures, e.Sig)
		}
		if !readable {
			continue
		}
		res, err := ValidateKELFromBytes(in)
		if err != nil || len(res.ValidationErrors) != 0 || !res.KelVerified {
			continue
		}
		l := readWitnessedAnswer{raws: in.RawEvents}
		var held []string
		for _, raw := range in.RawEvents {
			ev, err := keri.ParseEvent(raw)
			if err != nil {
				readable = false
				break
			}
			l.said = append(l.said, ev.SAID)
			after, _ := WitnessesAfter(held, ev)
			// Only a log its controller signed shows what its owner did, and this one is.
			if len(held) > 0 && len(after) == 0 {
				return nil, ErrWitnessesRefuse
			}
			held = after
		}
		if !readable {
			continue
		}
		for i, e := range a.KEL {
			for _, r := range e.Receipts {
				if !IsEventSignedReceipt(r.Sig) {
					continue
				}
				receipts[l.said[i]] = append(receipts[l.said[i]], WitnessReceipt{WitnessAID: r.Witness, CesrSignature: r.Sig})
			}
		}
		logs = append(logs, l)
	}
	if len(logs) == 0 {
		return nil, ErrNoWitnessedLog
	}
	var kept []readWitnessedAnswer
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
	if len(kept) == 0 {
		return nil, ErrNoWitnessedLog
	}
	best := 0
	for i := range kept {
		if through[i] > through[best] {
			best = i
		}
	}
	for i := range kept {
		for j := range kept {
			for k := 0; k < min(through[i], through[j]); k++ {
				if kept[i].said[k] != kept[j].said[k] {
					return nil, ErrWitnessesRefuse
				}
			}
		}
	}
	if through[best] == 0 {
		return nil, ErrNoWitnessedLog
	}
	return &WitnessedLog{SAIDs: kept[best].said[:through[best]]}, nil
}

// LinkVerdict is how the log a link carried stands to the log the witnesses
// vouch for.
type LinkVerdict string

const (
	// LinkAgrees: the link's log holds every event they vouch for (and perhaps more).
	LinkAgrees LinkVerdict = "agrees"
	// LinkMovedOn: they vouch for events after the link's last.
	LinkMovedOn LinkVerdict = "moved_on"
	// LinkApart: the two hold different events at one place.
	LinkApart LinkVerdict = "apart"
	// LinkNone: the witnesses gave no log to take.
	LinkNone LinkVerdict = "none"
	// LinkRefused: the witnesses prove the identifier unfit (ErrWitnessesRefuse).
	LinkRefused LinkVerdict = "refused"
)

// JudgeLinkLog is how linkSAIDs (the SAIDs of the events of the log a link
// carried, in order) stands to what the witnesses answered.
func JudgeLinkLog(rid string, linkSAIDs []string, answers []WitnessAnswer) LinkVerdict {
	w, err := ReadWitnessedLog(rid, answers)
	switch {
	case errors.Is(err, ErrWitnessesRefuse):
		return LinkRefused
	case err != nil:
		return LinkNone
	}
	hasPrefix := func(long, short []string) bool {
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
	switch {
	case hasPrefix(linkSAIDs, w.SAIDs):
		return LinkAgrees
	case hasPrefix(w.SAIDs, linkSAIDs):
		return LinkMovedOn
	}
	return LinkApart
}
