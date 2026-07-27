package linkverifier

// Outcome is the 4-value rendering driver.
type Outcome string

const (
	OutcomeVerified   Outcome = "verified"
	OutcomeTampered   Outcome = "tampered"
	OutcomeUnverified Outcome = "unverified"
	OutcomeIncomplete Outcome = "incomplete"
)

type InputKind string

const (
	InputURL       InputKind = "url"
	InputDIDWebs   InputKind = "did_webs"
	InputOOBI      InputKind = "oobi"
	InputQRPayload InputKind = "qr_payload"
)

type Flow string

const (
	FlowBadge Flow = "badge"
	FlowLink  Flow = "link"
)

type Timing string

const (
	TimingEager Timing = "eager"
	TimingLazy  Timing = "lazy"
)

type Tier string

const (
	TierFree  Tier = "free"
	TierGated Tier = "gated"
)

// VerifyRequest is the verify() input (the contract §2.1).
type VerifyRequest struct {
	Input        string    `json:"input"`
	InputKind    InputKind `json:"input_kind,omitempty"`
	Flow         Flow      `json:"flow"`
	Timing       Timing    `json:"timing,omitempty"`
	Tier         Tier      `json:"tier,omitempty"`
	GatingToken  string    `json:"gating_token,omitempty"`
	ForceRefresh bool      `json:"force_refresh,omitempty"`
}

// Ownership is the link-flow registration payload (the contract §4).
type Ownership struct {
	RegisteredTo string `json:"registered_to"`
	Disclosure   string `json:"disclosure"`
}

// VerificationResult is the verify() output (the contract §2.2).
type VerificationResult struct {
	Outcome            Outcome    `json:"outcome"`
	AID                *string    `json:"aid"`
	VerificationPath   string     `json:"verification_path"`
	KelReplay          string     `json:"kel_replay,omitempty"`
	LastVerified       string     `json:"last_verified"`
	ContactCorrelation *string    `json:"contact_correlation"`
	Ownership          *Ownership `json:"ownership,omitempty"`
	Band               string     `json:"band,omitempty"`
	BandStyle          string     `json:"band_style,omitempty"`
	// IdentityLevelScore and its timestamp are populated when a level provider
	// is configured and the caller is entitled to a gated result. The provider
	// that issued it is named in Badge.
	IdentityLevelScore     *int    `json:"identity_level_score,omitempty"`
	IdentityLevelScoreAsOf *string `json:"identity_level_score_as_of,omitempty"`
	Badge                  *string `json:"badge,omitempty"`
	Cached                 bool    `json:"cached,omitempty"`
}

// Config holds SDK options.
type Config struct {
	EagerCap int
	// LevelProvider names the identity-level provider this agent is configured
	// with, and is empty when there is none. It doubles as the badge the caller
	// sees, so the SDK never has to know which provider it is talking about.
	LevelProvider string
	ContactLookup func(aid string) (known bool, name string)
}
