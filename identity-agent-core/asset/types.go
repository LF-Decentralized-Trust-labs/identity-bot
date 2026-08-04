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
	RequiredBadge    string `json:"required_badge"`     // ""|"green"|"yellow"|"red"
	RequiredOFAScore int    `json:"required_ofa_score"` // 0 = not required
	// Credential gating: when RequiredCredSchema is set, a sign-in is authorized
	// only if the assertion presents a valid, unrevoked ACDC of that schema. If
	// RequiredCredIssuer is also set, the credential must have been issued by
	// that issuer AID (e.g. the org's own AID → an employee credential).
	RequiredCredSchema string `json:"required_cred_schema"` // schema SAID; "" = no credential required
	RequiredCredIssuer string `json:"required_cred_issuer"` // issuer AID; "" = any issuer
}

type Asset struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	AssetType   string `json:"asset_type"` // "domain" | "application"
	Origin      string `json:"origin"`
	PairwiseAID string `json:"pairwise_aid"`
	// PublicKey is the signing key of an asset that BROUGHT ITS OWN — a machine
	// that generated a keypair and enrolled with the public half.
	//
	// Empty for every asset the agent minted itself, and correctly so: those
	// keys are recoverable from SigningIndex and the owner's seed, so storing a
	// copy would add a second place for them to drift. An enrolled asset's key
	// is nowhere in that tree, so if it is not recorded here nothing can ever
	// verify anything the machine says.
	PublicKey string `json:"public_key,omitempty"`
	// MachineIDKind and MachineIDValue record WHICH PHYSICAL MACHINE enrolled,
	// captured at the one moment a person could vouch for it.
	//
	// Attestation proves what a machine is, never whose it is — the
	// manufacturer's key service answers to anybody, so a machine an attacker
	// owns attests as well as ours. Pinning to the value recorded here is what
	// turns "some machine of this make" into "the machine we enrolled".
	//
	// Empty when the machine could not be identified, with MachineIDWhy saying
	// so. Absent is a legitimate state — a machine without the hardware still
	// enrols — and it must stay distinguishable from identified, which is why
	// nothing here is ever filled in with a placeholder.
	MachineIDKind   string           `json:"machine_id_kind,omitempty"`
	MachineIDValue  string           `json:"machine_id_value,omitempty"`
	MachineIDWhy    string           `json:"machine_id_why,omitempty"`
	DelegationModel string           `json:"delegation_model"` // "delegated" | "standalone"
	DelegatorAID    string           `json:"delegator_aid,omitempty"`
	Policy          EnrollmentPolicy `json:"policy"`
	// SigningIndex is the HD derivation index (from the controller root seed) for this
	// asset's signing key. Re-derive the seed on demand (root + SigningIndex) — the
	// raw private key is never persisted. >0 means the asset can sign login challenges.
	SigningIndex int `json:"signing_index,omitempty"`
	// Capabilities is the capability ceiling for an ai_agent asset: the ids this
	// agent may invoke through the governed endpoint. It is the granted scope a
	// capability-endowment ACDC can later formalize; for now it is the
	// authoritative ceiling the gateway enforces. Empty for non-agent assets.
	Capabilities []string `json:"capabilities,omitempty"`
	// AgentConfig is the operational configuration of an ai_agent asset — beyond its
	// identity and capability ceiling: its role, system prompt, which LLM brain it
	// connects to, and how it is exposed. Nil for non-agent assets.
	AgentConfig *AgentConfig `json:"agent_config,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// AgentConfig captures what an ai_agent is and how it operates. The identity + grant
// (above) make it governed; this makes it usable.
type AgentConfig struct {
	Role         string      `json:"role,omitempty"`          // catalog role or short description
	SystemPrompt string      `json:"system_prompt,omitempty"` // the agent's instructions
	Brain        BrainConfig `json:"brain"`                   // how it reaches its LLM
	Exposure     Exposure    `json:"exposure"`                // how tools reach it
}

// BrainConfig is how an agent connects to its LLM (its probabilistic brain). Kept
// entirely separate from where the Identity Agent itself runs (its deterministic host).
type BrainConfig struct {
	// Kind: "cli" (a subscription CLI like Claude Code), "remote" (a hosted model over
	// an API), or "local" (a model on a local endpoint).
	Kind string `json:"kind,omitempty"`
	// Provider: cli → "claude-code"|"codex"|"grok"; remote → "anthropic"|"openrouter"|"xai".
	Provider string `json:"provider,omitempty"`
	Model    string `json:"model,omitempty"`
	// Endpoint is the base URL for a local (or self-hosted) model API.
	Endpoint string `json:"endpoint,omitempty"`
	// CredentialRef names the encrypted-vault entry holding the model API key. The key
	// itself is NEVER stored on the asset — only this reference.
	CredentialRef string `json:"credential_ref,omitempty"`
	// TEEAttestedOnly is a governance restriction: only a TEE-attested model may wear
	// this identity (brain-topology enforcement).
	TEEAttestedOnly bool `json:"tee_attested_only,omitempty"`
}

// Exposure is how an agent's capabilities are reached by tools and other agents.
type Exposure struct {
	MCP       bool `json:"mcp"`                  // on the Identity Agent's MCP server (default)
	DirectAPI bool `json:"direct_api,omitempty"` // a plain HTTPS endpoint for non-MCP callers
}

type AssetInvite struct {
	Token     string    `json:"token"`
	AssetID   string    `json:"asset_id"`
	Label     string    `json:"label,omitempty"`
	MaxUses   int       `json:"max_uses"` // 0 = unlimited (Slack-style default)
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
	// IsSigner marks the organisation-founding invite (t=4): redeeming it makes the
	// individual an ACTIVE super-admin immediately (they're a founding signer,
	// there's no one above them to approve), and requires a vouch signature.
	IsSigner  bool      `json:"is_signer,omitempty"`
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
	PairwiseAID    string `json:"pairwise_aid"`
	Name           string `json:"name"`
	Role           string `json:"role"`
	Status         string `json:"status"` // "pending"|"active"|"revoked"
	InviteToken    string `json:"invite_token,omitempty"`
	CredentialSAID string `json:"credential_said,omitempty"`
	OOBI           string `json:"oobi,omitempty"`
	// IsSigner and the vouch: set when this member is a founding signer of the
	// organisation.
	// VouchSig is the individual's signature over {signer_aid, org_aid} — the
	// org's stored proof that a real person stands behind it.
	IsSigner     bool      `json:"is_signer,omitempty"`
	VouchSig     string    `json:"vouch_sig,omitempty"`
	VouchPayload string    `json:"vouch_payload,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
