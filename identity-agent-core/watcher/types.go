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
}

// DuplicityAlert is an immutable fork-detection audit record.
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
	AID         string
	KEL         []map[string]interface{}
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
	sourcesQueried []SourceOutcome
	duplicityAlert *DuplicityAlert
	firstContact   bool
}
