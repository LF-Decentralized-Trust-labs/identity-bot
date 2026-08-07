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
type KelCheckRequest struct {
	AID    string `json:"aid"`
	Seq    int    `json:"seq"`
	Digest string `json:"digest"`
}

// KelCheckResponse is the watcher /public/kel-check response.
type KelCheckResponse struct {
	Match         bool    `json:"match"`
	OurDigest     *string `json:"our_digest"`
	OurFirstSeen  *string `json:"our_first_seen_at"`
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
type VerifyKelResult struct {
	OK              bool
	Blocked         bool
	Reason          string
	AID             string
	SequenceNum     int
	Digest          string
	OverallOutcome  string
	SourcesQueried  []SourceOutcome
	DuplicityAlert  *DuplicityAlert
	FirstContact    bool
}