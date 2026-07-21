package asset

import "time"

type EnrollmentMode string

const (
	EnrollmentOpen    EnrollmentMode = "open"
	EnrollmentRequest EnrollmentMode = "request"
	EnrollmentInvite  EnrollmentMode = "invite"
)

// EnrollmentPolicy is stored in full by OSS core.
// required_aal is enforced here (NIST 800-63B level 1/2/3).
// required_badge / required_ofa_score are stored and returned
// but enforcement is handled by the commercial layer on top.
type EnrollmentPolicy struct {
	Mode EnrollmentMode `json:"mode"`
	// MembershipSource selects which roster the membership gate consults when
	// Mode != "open". "" or "asset" = this asset's own member list (the built-in
	// path). Any other value (e.g. "employees") is resolved by a MembershipResolver
	// registered at runtime — see server.RegisterMembershipResolver. This is the
	// generic seam that lets an overlay (or a third-party org agent) gate login on
	// its own roster without forking the core; the core ships no non-default
	// resolvers, so an unrecognized source fails closed.
	MembershipSource string `json:"membership_source"` // ""|"asset"|<resolver key>
	RequiredAAL      int    `json:"required_aal"`
	RequiredBadge    string         `json:"required_badge"`      // ""|"green"|"yellow"|"red"
	RequiredOFAScore int            `json:"required_ofa_score"`  // 0 = not required
	// Credential gating: when RequiredCredSchema is set, a sign-in is authorized
	// only if the assertion presents a valid, unrevoked ACDC of that schema. If
	// RequiredCredIssuer is also set, the credential must have been issued by
	// that issuer AID (e.g. the org's own AID → an employee credential).
	RequiredCredSchema string `json:"required_cred_schema"` // schema SAID; "" = no credential required
	RequiredCredIssuer string `json:"required_cred_issuer"` // issuer AID; "" = any issuer
}

type Asset struct {
	ID              string           `json:"id"`
	DisplayName     string           `json:"display_name"`
	AssetType       string           `json:"asset_type"`       // "domain" | "application"
	Origin          string           `json:"origin"`
	PairwiseAID     string           `json:"pairwise_aid"`
	DelegationModel string           `json:"delegation_model"` // "delegated" | "standalone"
	DelegatorAID    string           `json:"delegator_aid,omitempty"`
	Policy          EnrollmentPolicy `json:"policy"`
	// SigningIndex is the HD derivation index (from the controller root seed) for this
	// asset's signing key. Re-derive the seed on demand (root + SigningIndex) — the
	// raw private key is never persisted. >0 means the asset can sign login challenges.
	SigningIndex    int              `json:"signing_index,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

type AssetInvite struct {
	Token     string    `json:"token"`
	AssetID   string    `json:"asset_id"`
	Label     string    `json:"label,omitempty"`
	MaxUses   int       `json:"max_uses"`   // 0 = unlimited (Slack-style default)
	UseCount  int       `json:"use_count"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
}

type AssetMember struct {
	AssetID     string    `json:"asset_id"`
	PairwiseAID string    `json:"pairwise_aid"`
	JoinedAt    time.Time `json:"joined_at"`
	InviteToken string    `json:"invite_token,omitempty"`
}

type AssetAccessRequest struct {
	ID            string            `json:"id"`
	AssetID       string            `json:"asset_id"`
	RequesterInfo map[string]string `json:"requester_info"`
	Status        string            `json:"status"` // "pending"|"approved"|"denied"
	CreatedAt     time.Time         `json:"created_at"`
	ResolvedAt    *time.Time        `json:"resolved_at,omitempty"`
}
