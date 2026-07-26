package server

import (
	"encoding/json"

	"identity-agent-core/store"
)

// The Ask / transaction registry. Every interaction between Identity Agents (login, add a
// contact, and the many types to come) is an "Ask": a signed, typed request fetched from a
// pointer URL. The action is an integer discriminator `t` (ADR-021's Ask registry). The
// SCANNER is a dumb router — it forwards the scanned URL to Go; Go fetches the Ask, reads `t`,
// runs the foundational OOBI layer (EnsureKeriContact), then dispatches to the hardcoded
// handler for that `t`. Adding a new transaction type = registering a new `t` here, nothing
// else changes.
//
// t = 1 -> login (the website/RP asks you to prove who you are)
// t = 2 -> add-contact (a peer asks to become a contact)
// t = … -> future actions, hundreds of them, each hardcoded.

// askEnvelope is just enough of any Ask to discover its action `t`. The handler decodes the
// full bytes into its own typed payload.
type askEnvelope struct {
	V string `json:"v"`
	T int    `json:"t"`
}

// AskContext carries everything a handler needs about one scanned transaction.
type AskContext struct {
	URL      string // the scanned pointer, e.g. https://host/path/i/{token}
	Base     string // the asker's base (URL minus the trailing /i/{token}, path preserved)
	Token    string // the session token (last path segment)
	AskBytes []byte // the raw Ask fetched from URL
	T        int    // action discriminator
	// Counterparty is the contact established by the foundational OOBI layer for this
	// transaction (the site for login, the peer for add-contact). May be nil if the action
	// resolves its counterparty itself.
	Counterparty *store.ContactRecord
}

// GenericPreview is the type-agnostic consent payload the scanner renders. No per-type logic
// lives in the scanner — it just shows this and collects a decision.
type GenericPreview struct {
	T            int             `json:"t"`
	Action       string          `json:"action"`                 // "login" | "add_contact" | …
	Title        string          `json:"title"`                  // "Sign-in request" | "Contact request"
	Subtitle     string          `json:"subtitle,omitempty"`     // audience / who is asking
	Counterparty string          `json:"counterparty,omitempty"` // AID or display name
	Details      []PreviewDetail `json:"details,omitempty"`      // fields being shared, etc.
	TierOptions  []string        `json:"tier_options,omitempty"` // e.g. add-contact: general/trusted/professional
	DefaultTier  string          `json:"default_tier,omitempty"`
	Warning      string          `json:"warning,omitempty"`

	// AskDigest is the Blake3 digest of the exact Ask bytes this preview
	// describes. The client echoes it back on execute so the agent can prove
	// it is acting on the same document the user saw — see bindConsent.
	AskDigest string `json:"ask_digest"`
}

type PreviewDetail struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// ScanDecision is the user's answer to a GenericPreview.
type ScanDecision struct {
	Approved bool   `json:"approved"`
	Tier     string `json:"tier,omitempty"` // chosen escalation tier for actions that take one
}

// TransactionHandler is the hardcoded behavior for one Ask action `t`.
type TransactionHandler interface {
	Action() string // stable name, e.g. "login"
	Preview(s *CoreServer, ctx AskContext) (GenericPreview, error)
	Execute(s *CoreServer, ctx AskContext, d ScanDecision) (map[string]interface{}, error)
}

var askRegistry = map[int]TransactionHandler{}

func registerAsk(t int, h TransactionHandler) { askRegistry[t] = h }

func lookupAsk(t int) (TransactionHandler, bool) { h, ok := askRegistry[t]; return h, ok }

// askActionType reads the `t` discriminator from raw Ask bytes.
func askActionType(askBytes []byte) (int, error) {
	var env askEnvelope
	if err := json.Unmarshal(askBytes, &env); err != nil {
		return 0, err
	}
	return env.T, nil
}
