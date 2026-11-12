package watcher

import "time"

// SourceType records how a KEL observation was obtained.
type SourceType string

const (
	SourceOOBI       SourceType = "oobi"
	SourceCredential SourceType = "credential"
	SourceManual     SourceType = "manual"
)

// L2TrustGrade distinguishes bootstrap (controller-hinted) vs standing (verifier-selected).
type L2TrustGrade string

const (
	L2Bootstrap L2TrustGrade = "bootstrap"
	L2Standing  L2TrustGrade = "standing"
)

// FirstSeenRecord is a row in kel_first_seen.
type FirstSeenRecord struct {
	AID             string
	SequenceNum     int
	KelDigest       string
	FirstSeenAt     time.Time
	LastConfirmedAt time.Time
	SeenCount       int
	SourceType      SourceType
	SourceURL       string
	// Proven is whether the log first seen verified under its own controller's
	// signatures. A digest from a log that did not is remembered but never
	// contradicted into a refusal.
	Proven bool
}

// DuplicityAlert is an immutable fork-detection audit record.
// The kinds of alert. Only a duplicity alert blocks.
const (
	AlertKindDuplicity  = "duplicity"
	AlertKindEscalation = "escalation"
	// AlertKindWatcher is about a standing watcher, not about the contact: its
	// answer did not hold up when checked (its log does not verify, or does not
	// match its own digest). The contact is not held for it.
	AlertKindWatcher = "watcher"
)

type DuplicityAlert struct {
	ID             int64
	AID            string
	SequenceNum    int
	OurDigest      string
	TheirDigest    string
	SourceURL      string
	DetectedAt     time.Time
	Resolved       bool
	ResolutionNote string
	// Kind is AlertKindDuplicity (blocks the log it is about until resolved) or
	// AlertKindEscalation (the standing watcher disagreed: shown, never blocks). Empty means
	// duplicity.
	Kind string
	// Evidence is what the alert rests on, as JSON (see Evidence in
	// proof_of_duplicity.go): for duplicity the two signed events at the
	// contested place, for a watcher alert why its answer was set aside. Empty
	// on an alert that was raised without any.
	Evidence string
	// AcknowledgedAt is empty until the owner has seen the alert. An alert
	// stays one until it is resolved.
	AcknowledgedAt time.Time
}

// DigestResponse is the watcher /public/kel-digest contract.
type DigestResponse struct {
	AID            string  `json:"aid"`
	SequenceNumber int     `json:"sequence_number"`
	Digest         *string `json:"digest"`
	ObservedSince  *string `json:"observed_since"`
	FirstSeenAt    *string `json:"first_seen_at"`
	SignedBy       string  `json:"signed_by,omitempty"`
	Signature      string  `json:"signature,omitempty"`
}

// KelCheckRequest is the watcher /public/kel-check contract.
//
// The caller proves it already holds the log by giving its digest; Requester,
// At and Signature say who asked and bind the question to one peer and moment
// (see KelCheckRequestStatement).
type KelCheckRequest struct {
	AID       string `json:"aid"`
	Seq       int    `json:"seq"`
	Digest    string `json:"digest"`
	Requester string `json:"requester,omitempty"`
	At        int64  `json:"at,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// KelCheckResponse is the watcher /public/kel-check response: whether the
// caller's digest is the one held, and nothing else. A watcher that has never
// seen the identity, one that holds a different digest and one whose owner
// opted out all answer the same "no match", so the answer cannot be used to
// find out whom its owner deals with.
type KelCheckResponse struct {
	Match bool `json:"match"`
}

// SourceOutcome tracks one layer in a verification pass.
type SourceOutcome struct {
	Type      string `json:"type"`
	URL       string `json:"url,omitempty"`
	Outcome   string `json:"outcome"`
	LatencyMs int    `json:"latency_ms,omitempty"`
}

// VerifyKelInput is passed from OOBI/credential hooks.
type VerifyKelInput struct {
	AID string
	KEL []map[string]interface{}
	// Signed is the presented log's own signed bytes, one message per event, as
	// keri.ValidateSignedKEL judges them. Empty when the route holds only parsed
	// records; NotSigned then says which event could not be carried, and the log
	// is not proven by this input.
	Signed      [][]byte
	NotSigned   string
	SourceType  SourceType
	SourceURL   string
	BootstrapL2 []string // OOBI watchers hints (advisory)
}

// VerifyKelResult is returned to callers after L1+L2 evaluation.
//
// What the watcher had seen before (whether this was a first contact, each
// source's outcome, the alert with the digest it held) stays unexported: a
// caller in another package gets the verdict and its reason, never a way to
// read an observation around the opt-out check.
type VerifyKelResult struct {
	OK             bool
	Blocked        bool
	Reason         string
	AID            string
	SequenceNum    int
	Digest         string
	OverallOutcome string
	// Latest is set when a standing watcher held validly signed later events
	// than the log presented (or a recovery rotation replacing its later
	// interactions): the verified log with them admitted, as signed messages,
	// the keys now in force and its last sequence number. A caller verifies
	// anything signed against these, not against the presented log's keys,
	// which a rotation may have retired.
	Latest          [][]byte
	LatestKeys      []string
	LatestRecords   []map[string]interface{} // the same log as records, in the shape callers hold
	LatestSeq       int
	FlaggedWatchers []string // standing watchers whose answer did not hold up
	sourcesQueried  []SourceOutcome
	duplicityAlert  *DuplicityAlert
	firstContact    bool
}

// Verdicts of a check of one identity's key log.
const (
	VerdictConfirmed  = "confirmed"  // no source disagreed
	VerdictDuplicity  = "duplicity"  // two histories were seen for the same event
	VerdictUnreadable = "unreadable" // the log could not be placed
	VerdictEscalated  = "escalated"  // the standing watcher disagreed; shown to the owner, nothing was blocked
)

// Outcomes a source gave in a check, as the owner is told them. A source's
// own outcome is "agrees" or "disagrees", or says why it could not answer.
const (
	OutcomeAgrees      = "agrees"
	OutcomeDisagrees   = "disagrees"
	OutcomeNoAnswer    = "no_answer"   // reached, but had not seen this identity
	OutcomeUnreachable = "unreachable" // could not be asked
	OutcomeAhead       = "ahead"       // holds validly signed later events: the presented log was stale
	OutcomeBehind      = "behind"      // holds an older branch that a recovery rotation supersedes
	OutcomeFaulty      = "faulty"      // its answer did not hold up when checked
)

// CheckSource is what one source said in the newest check of an identity.
// Type is "own_record", "standing", "hint" or "peer". It never carries a digest,
// and the own record's "seen before or not" is folded into "agrees", so this
// reveals nothing the opt-out check exists to hide.
type CheckSource struct {
	Type    string `json:"type"`
	URL     string `json:"url,omitempty"`
	Outcome string `json:"outcome"`
}

// ContactCheck is the newest check of one identity: when, the verdict, and what
// each source said. A contact that has never been checked has none, which is
// not the same as one whose check found nothing wrong.
type ContactCheck struct {
	AID       string        `json:"aid"`
	CheckedAt string        `json:"checked_at"`
	Verdict   string        `json:"verdict"`
	Reason    string        `json:"reason,omitempty"`
	Sources   []CheckSource `json:"sources"`
}

// Stopped says a caller must not go ahead on this result: the log forks, proven
// (Blocked).
func (r *VerifyKelResult) Stopped() bool { return r.Blocked }

// Check summarises a result for the owner. The per-source detail is folded here,
// at the one place it is read, so what leaves the package is the summary and
// not the observation.
func (r *VerifyKelResult) Check() ContactCheck {
	c := ContactCheck{
		AID: r.AID, CheckedAt: time.Now().UTC().Format(time.RFC3339),
		Verdict: VerdictConfirmed, Reason: r.Reason, Sources: []CheckSource{},
	}
	switch {
	case r.OverallOutcome == "unreadable":
		c.Verdict = VerdictUnreadable
	case r.Blocked:
		c.Verdict = VerdictDuplicity
	case r.OverallOutcome == "escalated":
		c.Verdict = VerdictEscalated
	}
	for _, so := range r.sourcesQueried {
		cs := CheckSource{URL: so.URL}
		switch so.Type {
		case "L1":
			cs.Type = "own_record"
		case "L2_standing":
			cs.Type = "standing"
		case "L2_bootstrap":
			cs.Type = "hint"
		default:
			cs.Type = "peer"
		}
		switch so.Outcome {
		case "first_seen", "match", "confirmed":
			cs.Outcome = OutcomeAgrees
		case "mismatch", "fork":
			cs.Outcome = OutcomeDisagrees
		case "ahead", "superseded":
			cs.Outcome = OutcomeAhead
		case "behind":
			cs.Outcome = OutcomeBehind
		case "faulty":
			cs.Outcome = OutcomeFaulty
		case "unavailable", "unreachable", "error":
			cs.Outcome = OutcomeUnreachable
		default:
			cs.Outcome = OutcomeNoAnswer
		}
		// The own record cannot "have no answer"; it either held or it did not.
		if cs.Type == "own_record" && cs.Outcome == OutcomeNoAnswer {
			cs.Outcome = OutcomeAgrees
		}
		c.Sources = append(c.Sources, cs)
	}
	return c
}
