package witness

import "time"

// Witness protocol constants.
const (
	MaxWitnessSetSize       = 9
	TargetContactWitnesses  = 7
	DefaultThreshold        = 5 // majority of 9
	MaxOutgoingWitnessing   = 15
	HeartbeatInterval       = 15 * time.Minute
	HeartbeatTimeout        = 5 * time.Second
	OfflineFailureThreshold = 4
	FinalizeWaitDuration    = 60 * time.Second
	SelfHealMaxPerHour      = 3
	SelfHealCooldown        = 24 * time.Hour
	BroadcastRetryDelay     = 30 * time.Second
)

const (
	BackendDesktop  = "desktop"
	BackendHosted   = "hosted" // black-box / attestation-backed rented infra
	BackendMobile   = "mobile"
	BackendCommercial = "commercial"
)

const (
	StatusOnline  = "online"
	StatusOffline = "offline"
	StatusPending = "pending"
)

const (
	FinalizePending    = "pending"
	FinalizePartial    = "partial"
	FinalizeFinalized  = "finalized"
	FinalizeTimeout    = "timeout"
)

const (
	ContactSourceManual        = "manual"
	ContactSourceTransactional = "transactional"
)

// AidKind distinguishes Root vs Pairwise witnessing pools (OQ-W2).
type AidKind string

const (
	AidKindRoot     AidKind = "root"
	AidKindPairwise AidKind = "pairwise"
)

// ContactMeta is per-contact witness pool metadata (D1/D3).
type ContactMeta struct {
	ContactAID      string
	BackendType     string
	WitnessStatus   string
	OfflineCount    int
	IsMutual        bool
	IsCommercial    bool
	WitnessingFor   bool // true when we witness FOR this contact (outgoing)
	EnrolledAt      string
	LastReceiptAt   string
	LastHealthCheck string
}

// KelEvent is a stored KEL replica entry (D2).
type KelEvent struct {
	SignerAID    string
	SequenceNum  int
	EventJSON    string
	EventSAID    string
	StoredAt     string
}

// IssuedReceipt is a CESR receipt this agent issued as witness.
type IssuedReceipt struct {
	SignerAID     string
	EventSAID     string
	SequenceNum   int
	WitnessAID    string
	ReceiptJSON   string
	CesrSignature string
	IssuedAt      string
}

// FinalizationState tracks broadcast receipt collection (D4).
type FinalizationState struct {
	EventSAID     string
	SignerAID     string
	SequenceNum   int
	State         string
	ReceiptCount  int
	Threshold     int
	StartedAt     string
	UpdatedAt     string
}

// StatusResponse is the status-interface shape for the Witnesses tab.
type StatusResponse struct {
	ActiveCount       int              `json:"active_count"`
	Threshold         int              `json:"threshold"`
	MaxWitnesses      int              `json:"max_witnesses"`
	OutgoingCapacity  int              `json:"outgoing_capacity"`
	OutgoingUsed      int              `json:"outgoing_used"`
	BackendType       string           `json:"backend_type"`
	WitnessCapacityOK bool             `json:"witness_capacity_available"`
	YourWitnesses     []WitnessEntry   `json:"your_witnesses"`
	WitnessingFor     []WitnessingEntry `json:"witnessing_for"`
}

type WitnessEntry struct {
	AID           string `json:"aid"`
	Alias         string `json:"alias"`
	BackendType   string `json:"backend_type"`
	Status        string `json:"status"`
	IsMutual      bool   `json:"is_mutual"`
	IsCommercial  bool   `json:"is_commercial"`
	OfflineCount  int    `json:"offline_count"`
	LastReceiptAt string `json:"last_receipt_at,omitempty"`
}

type WitnessingEntry struct {
	SignerAID  string `json:"signer_aid"`
	Alias      string `json:"alias"`
	EventCount int    `json:"event_count"`
	Since      string `json:"since"`
}