package witness

import (
	"time"

	"identity-agent-core/store"
)

// Witness protocol constants.
const (
	MaxWitnessSetSize      = 9
	TargetContactWitnesses = 7
	DefaultThreshold       = 5 // majority of 9
	MaxOutgoingWitnessing  = 15
	HeartbeatInterval      = 15 * time.Minute
	HeartbeatTimeout       = 5 * time.Second

	// OfflineTolerance is how long a witness may be unreachable before this
	// agent stops relying on it.
	//
	// Generous on purpose, and it used to be an hour. Dropping a witness early
	// buys nothing: during an outage its receipts do not arrive whether or not
	// we have written it off, so the threshold is already short either way. All
	// dropping decides is when to go looking for a REPLACEMENT — and replacing
	// means a rotation, which changes the identity's keys.
	//
	// It costs something, too. While the key log still designates a witness,
	// dropping it locally leaves this agent disagreeing with its own published
	// record of who watches it, and only a rotation reconciles that. So a
	// witness that reboots, moves house or loses power for a day should be
	// waited for, not replaced.
	//
	// The question this answers is "am I confident it is not coming back",
	// which is days, not minutes.
	OfflineTolerance = 72 * time.Hour

	// OfflineFailureThreshold is that tolerance in consecutive failed checks.
	//
	// Derived rather than written down, so the two cannot drift apart: changing
	// the heartbeat interval used to silently change how long a witness was
	// given, because the count was a bare number that read as if it meant
	// something on its own.
	OfflineFailureThreshold = int(OfflineTolerance / HeartbeatInterval)
	FinalizeWaitDuration    = 60 * time.Second
	SelfHealMaxPerHour      = 3
	SelfHealCooldown        = 24 * time.Hour
	BroadcastRetryDelay     = 30 * time.Second
)

const (
	BackendDesktop    = "desktop"
	BackendHosted     = "hosted" // black box: attestation-backed, run for the owner
	BackendMobile     = "mobile"
	BackendCommercial = "commercial"
)

// A witness is one of two classes (ADR-070). The class is what a person is
// told when they are told who their witnesses are, and what is sent on the
// wire; IsCommercial remains alongside it for clients that read the boolean.
const (
	// ClassPeer is another Identity Agent acting as a witness for a contact.
	ClassPeer = "PEER"
	// ClassCommercial is a Service Provider running witnessing as a product.
	ClassCommercial = "COMMERCIAL"
)

// ClassOf names the class of a witness from its commercial flag.
func ClassOf(isCommercial bool) string {
	if isCommercial {
		return ClassCommercial
	}
	return ClassPeer
}

const (
	StatusOnline  = "online"
	StatusOffline = "offline"
	StatusPending = "pending"
)

const (
	FinalizePending   = "pending"
	FinalizePartial   = "partial"
	FinalizeFinalized = "finalized"
	FinalizeTimeout   = "timeout"
)

const (
	ContactSourceManual        = "manual"
	ContactSourceTransactional = "transactional"
	// ContactSourceInbound marks a contact a stranger's request created: what
	// it recorded about itself, its address among it, is the stranger's.
	ContactSourceInbound = "inbound"
	// ContactSourceInboundConfirmed is such a contact once the owner has
	// accepted it: accepting is the owner confirming the address it gave.
	ContactSourceInboundConfirmed = "inbound_confirmed"
)

// AidKind distinguishes Root vs Pairwise witnessing pools. The two draw from
// different sets of witnesses: see ContactWitnessAllowedForAID.
type AidKind string

const (
	AidKindRoot     AidKind = "root"
	AidKindPairwise AidKind = "pairwise"
)

// ContactMeta is per-contact witness pool metadata (D1/D3).
type ContactMeta struct {
	ContactAID string
	// BackendType is what this contact runs on, taken from what it publishes.
	//
	// It decides whether the contact can witness at all: witnessing means being
	// reachable when somebody else's event needs receipting, and a phone is
	// not. A phone paired to a computer is, because the computer answers — so
	// what matters is whether there is an always-on backend, not what the
	// person carries. Where that backend is hosted makes no difference.
	BackendType string
	// WitnessKey is the non-transferable key this contact signs receipts with,
	// as published in its OOBI. Empty when it publishes none, in which case it
	// can be asked to witness but can never be designated — what an event names
	// is the key, not the contact.
	WitnessKey string
	// EntityType is whether this contact is a person or an organization.
	//
	// It decides whether they may witness for us at all: the two kinds are kept
	// apart, because a witness list is public and permanent and an individual's
	// root identifier is meant to stay unexposed. See PeerAllowedAcross.
	EntityType      string
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
	SignerAID   string
	SequenceNum int
	EventJSON   string
	EventSAID   string
	StoredAt    string
	// RawBytesB64 is the event exactly as the controller published it, and
	// CesrSignature is the controller's signature over those bytes.
	//
	// EventJSON substitutes for neither. It is re-encoded from the parsed
	// event, which sorts the fields, so it digests to something that is not the
	// event's identifier and a signature checked against it verifies nothing.
	// Without these a witness cannot establish that the controller authorised
	// what it is attesting to — which is the whole of what its receipt is worth.
	//
	// Empty for events stored before a witness kept them.
	RawBytesB64   string
	CesrSignature string
	// Signatures are the controller signatures over the event that verified
	// when it arrived or since, as attached. Empty on events stored before a
	// witness kept them, which hold CesrSignature only.
	Signatures []string
}

// ControllerSignatures are the controller signatures held for the event.
func (e KelEvent) ControllerSignatures() []string {
	return store.ControllerSignaturesOf(e.Signatures, e.CesrSignature)
}

// KelConflict is a correctly signed event that arrived at a place this witness
// already holds a different event at, and could not replace it. Kept with the
// held event's SAID, the pair is evidence of duplicity.
type KelConflict struct {
	SignerAID   string
	SequenceNum int
	EventSAID   string
	RawBytesB64 string
	Signatures  []string
	HeldSAID    string
	SeenAt      string
}

// TELEvent is one event of a registry's transaction log as a witness holds it:
// a registry inception, an issuance or a revocation, as the issuer published it.
type TELEvent struct {
	IssuerAID string `json:"-"`
	// SAID is the event's own identifier.
	SAID string `json:"said"`
	// Registry is the registry the event belongs to.
	Registry string `json:"registry"`
	// Ilk is "vcp", "iss" or "rev".
	Ilk string `json:"ilk"`
	// Subject is what the event is about: the registry for "vcp", the
	// credential otherwise.
	Subject string `json:"-"`
	// SN is the event's place in its own log (a credential's, or 0 for a registry).
	SN int `json:"sn"`
	// AnchorSN is the sequence number of the event in the issuer's key log whose
	// seal vouches for this one.
	AnchorSN int `json:"anchor_sn"`
	// RawB64 is the event exactly as published, base64.
	RawB64   string `json:"raw_b64"`
	StoredAt string `json:"-"`
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
	EventSAID    string
	SignerAID    string
	SequenceNum  int
	State        string
	ReceiptCount int
	Threshold    int
	StartedAt    string
	UpdatedAt    string
}

// StatusResponse is the status-interface shape for the Witnesses tab.
type StatusResponse struct {
	ActiveCount       int               `json:"active_count"`
	Threshold         int               `json:"threshold"`
	MaxWitnesses      int               `json:"max_witnesses"`
	OutgoingCapacity  int               `json:"outgoing_capacity"`
	OutgoingUsed      int               `json:"outgoing_used"`
	BackendType       string            `json:"backend_type"`
	WitnessCapacityOK bool              `json:"witness_capacity_available"`
	YourWitnesses     []WitnessEntry    `json:"your_witnesses"`
	WitnessingFor     []WitnessingEntry `json:"witnessing_for"`
}

type WitnessEntry struct {
	AID           string `json:"aid"`
	Alias         string `json:"alias"`
	BackendType   string `json:"backend_type"`
	Status        string `json:"status"`
	IsMutual      bool   `json:"is_mutual"`
	IsCommercial  bool   `json:"is_commercial"`
	Class         string `json:"class"` // ClassPeer or ClassCommercial
	OfflineCount  int    `json:"offline_count"`
	LastReceiptAt string `json:"last_receipt_at,omitempty"`
}

type WitnessingEntry struct {
	SignerAID  string `json:"signer_aid"`
	Alias      string `json:"alias"`
	EventCount int    `json:"event_count"`
	Since      string `json:"since"`
}
