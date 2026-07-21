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
	Mode             EnrollmentMode `json:"mode"`
	RequiredAAL      int            `json:"required_aal"`
	RequiredBadge    string         `json:"required_badge"`      // ""|"green"|"yellow"|"red"
	RequiredOFAScore int            `json:"required_ofa_score"`  // 0 = not required
	// Credential gating: when RequiredCredSchema is set, a sign-in is authorized
	// only if the assertion presents a valid, unrevoked ACDC of that schema. If
	// RequiredCredIssuer is also set, the credential must have been issued by
	// that issuer AID (e.g. the org's own AID → an employee credential).
	RequiredCredSchema string `json:"required_cred_schema"` // schema SAID; "" = no credential required
	RequiredCredIssuer string `json:"required_cred_issuer"` // issuer AID; "" = any issuer
	// MembershipSource selects which roster the membership gate consults when
	// Mode != "open". "" or "asset" = this asset's own members (asset invites).
	// "employees" = the org's employee roster, and only ACTIVE employees pass —
	// this is how an org gates its own portal by "must be a current employee".
	MembershipSource string `json:"membership_source"` // ""|"asset"|"employees"
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

// EmployeeInvite is an org-scoped (not asset-scoped) invitation to join the org
// as an employee. Redeeming it via the add_employee (t=3) action creates a
// pending Employee. MaxUses mirrors AssetInvite (0 = unlimited; 1 = a single
// named hire). The token is rendered as a QR code / link by the org app.
type EmployeeInvite struct {
	Token   string `json:"token"`
	Role    string `json:"role"`
	Label   string `json:"label,omitempty"`
	MaxUses int    `json:"max_uses"` // 0 = unlimited
	// The portal (asset) this employment grants access to. The accepting employee
	// derives their stable per-site pairwise AID against SiteAID during add_employee,
	// so it equals the AID they later present at that portal's login (AID method).
	AssetID  string `json:"asset_id,omitempty"`
	SiteAID  string `json:"site_aid,omitempty"`
	SiteOOBI string `json:"site_oobi,omitempty"`
	// IsSponsor marks the org-creation sponsor invite (t=4): redeeming it makes the
	// individual an ACTIVE super-admin immediately (they're the founding sponsor,
	// there's no one above them to approve), and requires a vouch signature.
	IsSponsor bool      `json:"is_sponsor,omitempty"`
	UseCount  int       `json:"use_count"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
}

// Employee is a first-class org roster entry — employment is org-scoped, not
// asset-scoped, so it has its own lifecycle (pending → active → revoked) rather
// than reusing AssetMember. The PairwiseAID is the AID the employee established
// with the org during add_employee; the membership gate (MembershipSource ==
// "employees") admits only Status == "active" entries. CredentialSAID records
// the issued Employee-Authorization ACDC (set on approval).
type Employee struct {
	PairwiseAID    string    `json:"pairwise_aid"`
	Name           string    `json:"name"`
	Role           string    `json:"role"`
	Status         string    `json:"status"` // "pending"|"active"|"revoked"
	InviteToken    string    `json:"invite_token,omitempty"`
	CredentialSAID string    `json:"credential_said,omitempty"`
	OOBI           string    `json:"oobi,omitempty"`
	// IsSponsor + the vouch: set when this employee is the org's founding sponsor.
	// VouchSig is the individual's signature over {sponsor_aid, org_aid} — the
	// org's stored proof that a real person stands behind it.
	IsSponsor    bool      `json:"is_sponsor,omitempty"`
	VouchSig     string    `json:"vouch_sig,omitempty"`
	VouchPayload string    `json:"vouch_payload,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
