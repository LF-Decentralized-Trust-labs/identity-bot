package watcher

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	keri "github.com/grapeid/keri-go"
)

// A contact is refused on proof of duplicity, never on a count of watchers.
//
// A standing watcher answers a digest. When its digest differs from the log a
// contact presented, the digest alone cannot say who is wrong: the presenter may
// have forked its log, or the watcher may be broken or lying. So the watcher is
// asked for its copy of the log with the controller signatures, and this file
// judges the two with keri-go, which is also what a witness uses (see
// witness/an_event_is_admitted_to_the_log_it_follows.go):
//
//   - the watcher's log must itself verify (self-certifying inception, every
//     event signed by the key state in force); one that does not is the
//     watcher's fault, not the contact's;
//   - each event of it that the presented log does not hold is admitted to the
//     presented log with SignedKELResult.Admit, which applies KERI's rule that a
//     recovery rotation replaces only the interactions after the last
//     establishment event;
//   - a different event at a place the presented log holds, correctly signed
//     under the state before that place, is two histories signed by the one
//     controller: duplicity, proven by the two events, whoever hands them over.
//
// One watcher's evidence is enough, because a watcher cannot forge a controller
// signature. Nothing here counts watchers.

// proofKind is what judging a watcher's log against the presented log found.
type proofKind int

const (
	// proofUnprovable is a disagreement that cannot be settled: the presented
	// log came without its signed bytes, or does not verify, or the watcher
	// would not hand its log over, or the disagreement turns on a delegator's
	// log (a delegated rotation at a taken place, which keri-go refuses and says
	// is not by itself duplicity). Shown to the owner, blocks nothing.
	proofUnprovable proofKind = iota
	// proofFork is two events at one place, each validly signed: duplicity.
	proofFork
	// proofWatcherFaulty is a watcher whose answer does not hold up: its log does
	// not verify, or it holds exactly the presented log yet gave another digest.
	proofWatcherFaulty
	// proofAhead is a watcher holding validly signed later events the presented
	// log lacks. The presenter showed a stale key state.
	proofAhead
	// proofSuperseded is a recovery rotation settling a place the two logs hold
	// differently: not duplicity. When the watcher's log carries the rotation the
	// presented log is stale (adopted, as for proofAhead); when the presented log
	// carries it the watcher is merely behind.
	proofSuperseded
	// proofWatcherBehind is a watcher that holds an older branch the presented log
	// supersedes by recovery.
	proofWatcherBehind
)

func (k proofKind) String() string {
	return [...]string{"unprovable", "duplicity", "faulty", "ahead", "superseded", "behind"}[k]
}

// WatcherLog is the log a watcher served for an identity: its own copy as signed
// messages, and any other events it kept at places it already held something
// else at, so it can hand over the conflicting branch it saw and not only the
// first one.
type WatcherLog struct {
	Messages [][]byte
	// Records are the same events as the records the watcher served, one per
	// message, so an adopted log can be handed on in the shape callers hold.
	Records []map[string]interface{}
	Rival   [][]byte
}

// Evidence is what an alert rests on.
type Evidence struct {
	Kind        string `json:"kind"` // "duplicity" or "watcher"
	SequenceNum int    `json:"sequence_number"`
	// HeldMessage and RivalMessage are the two signed events at the contested
	// place, each as an event with its attached signatures (base64). Anyone can
	// verify either with keri.VerifyEvent against the state before the place.
	HeldMessage  string `json:"held_message_b64,omitempty"`
	RivalMessage string `json:"rival_message_b64,omitempty"`
	// Watcher is the standing watcher the rival event came from, or the one flagged.
	Watcher string `json:"watcher,omitempty"`
	// Why says, for a watcher alert, how its answer did not hold up.
	Why string `json:"why,omitempty"`
}

func (e Evidence) json() string {
	b, _ := json.Marshal(e)
	return string(b)
}

// proof is the outcome of judging one watcher's log.
type proof struct {
	Kind     proofKind
	Reason   string
	Evidence *Evidence
	// Latest is, for proofAhead and proofSuperseded, the verified log with the
	// watcher's later events admitted, and LatestMessages its signed messages.
	Latest         *keri.SignedKELResult
	LatestMessages [][]byte
	LatestRecords  []map[string]interface{}
}

// judgeWatcherLog is the classifier. presented are the presented log's signed
// messages, in order.
func judgeWatcherLog(aid string, presented [][]byte, theirs *WatcherLog) proof {
	cur, err := keri.ValidateSignedKEL(presented)
	if err != nil {
		return proof{Kind: proofUnprovable, Reason: "the presented log does not verify: " + err.Error()}
	}
	if cur.Identifier != aid {
		return proof{Kind: proofUnprovable, Reason: "the presented log is for another identity"}
	}
	if len(theirs.Messages) == 0 {
		return proof{Kind: proofWatcherFaulty, Reason: "it gave a digest but holds no log to show for it"}
	}
	theirLog, err := keri.ValidateSignedKEL(theirs.Messages)
	if err != nil {
		return proof{Kind: proofWatcherFaulty, Reason: "its log does not verify: " + err.Error()}
	}
	if theirLog.Identifier != aid {
		return proof{Kind: proofWatcherFaulty, Reason: "its log is for another identity"}
	}

	msgs := append([][]byte(nil), presented...) // the messages of cur, by place
	moved, superseding := false, false

	// conflict judges an event at a place cur holds something else at.
	conflict := func(ev *keri.Event, message []byte) (*proof, bool) {
		if ev.Ilk == "drt" {
			p := proof{Kind: proofUnprovable, Reason: "a delegated rotation at a place already held: " +
				"whether it may replace the held event turns on its delegator's log, which is not by itself duplicity"}
			return &p, true
		}
		var before *keri.KeyState
		if ev.SN > 0 {
			before = cur.StateAt(ev.SN - 1)
		}
		if _, err := keri.VerifyEvent(before, message); err != nil {
			return &proof{Kind: proofWatcherFaulty, Reason: "an event of its log at place " +
				fmt.Sprint(ev.SN) + " does not verify against the state before it: " + err.Error()}, true
		}
		// The held event may be the one a recovery rotation retires. If the
		// presented event at this place is a recovery rotation the watcher's own
		// log could admit, the watcher is behind and nothing is duplicitous.
		if int(ev.SN) < len(msgs) {
			if adm, err := theirLog.Admit(msgs[ev.SN]); err == nil && adm.Supersedes > 0 {
				return &proof{Kind: proofWatcherBehind, Reason: "the presented log holds a recovery rotation " +
					"at place " + fmt.Sprint(ev.SN) + " that supersedes what the watcher holds"}, true
			}
		}
		return &proof{Kind: proofFork, Reason: fmt.Sprintf("two validly signed events at place %d", ev.SN),
			Evidence: &Evidence{
				Kind: "duplicity", SequenceNum: int(ev.SN),
				HeldMessage:  base64.StdEncoding.EncodeToString(msgs[ev.SN]),
				RivalMessage: base64.StdEncoding.EncodeToString(message),
			}}, true
	}

	// admit takes one event of the watcher's into cur. It returns a proof when
	// that settles the matter.
	admit := func(message []byte, rival bool) *proof {
		ev, err := keri.ParseEvent(message)
		if err != nil {
			return &proof{Kind: proofWatcherFaulty, Reason: "an event of its log does not parse"}
		}
		if ev.Identifier != aid {
			return &proof{Kind: proofWatcherFaulty, Reason: "an event of its log belongs to another identity"}
		}
		if held := cur.StateAt(ev.SN); held != nil && held.Digest() == ev.SAID {
			return nil // the same event
		}
		adm, err := cur.Admit(message)
		var ve *keri.ValidationError
		switch {
		case err == nil:
			if rival {
				return nil // a second branch of the watcher's does not move this log
			}
			if adm.Supersedes > 0 {
				superseding = true
			}
			msgs = append(msgs[:len(msgs)-adm.Supersedes], message)
			cur, moved = adm.Log, true
			return nil
		case errors.As(err, &ve) && ve.Has(keri.FaultPlaceTaken):
			p, _ := conflict(ev, message)
			return p
		case errors.As(err, &ve) && ve.Has(keri.FaultSequenceSkip) && rival:
			return nil // a branch beyond what the presented log holds says nothing about it
		default:
			return &proof{Kind: proofWatcherFaulty, Reason: "an event of its log is refused by the presented log's own rules: " + err.Error()}
		}
	}

	// A recovery rotation of the presented log over the watcher's older branch
	// settles the whole branch: the events after it are the retired ones.
	settle := func(p *proof) (proof, bool) {
		if p == nil {
			return proof{}, false
		}
		return *p, true
	}
	for _, m := range theirs.Messages {
		if p, done := settle(admit(m, false)); done {
			return p
		}
	}
	for _, m := range theirs.Rival {
		if p, done := settle(admit(m, true)); done {
			return p
		}
	}
	switch {
	case superseding:
		return proof{Kind: proofSuperseded, Reason: "a recovery rotation the watcher holds replaces the presented log's later interactions",
			Latest: cur, LatestMessages: msgs}
	case moved:
		return proof{Kind: proofAhead, Reason: "the watcher holds later signed events the presented log lacks",
			Latest: cur, LatestMessages: msgs}
	}
	return proof{Kind: proofWatcherFaulty, Reason: "it gave a digest that differs from the presented log, " +
		"yet its own log holds exactly the presented events"}
}
