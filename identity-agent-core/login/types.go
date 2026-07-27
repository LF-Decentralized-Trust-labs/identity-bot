package login

// ChallengeBundle is the login Ask (the login contract §2 / the shared module): v="ASK1", t=1 (login
// action). The IA fetches it from the minimal QR pointer (/i/{token}) and
// verifies its signature against the site KEL before showing consent.
type ChallengeBundle struct {
	V                    string                `json:"v"`
	T                    int                   `json:"t"`
	SiteAID              string                `json:"site_aid"`
	SiteOOBI             string                `json:"site_oobi"`
	Audience             string                `json:"audience"`
	Nonce                string                `json:"nonce"`
	Dt                   string                `json:"dt"`
	Expiry               string                `json:"expiry"`
	RequestedDisclosures []string              `json:"requested_disclosures"`
	RequestedCredentials []RequestedCredential `json:"requested_credentials"`
	RequestedScore       *RequestedScore       `json:"requested_score,omitempty"`
	CallbackURL          string                `json:"callback_url"`
	SessionToken         string                `json:"session_token"`
	// Membership-gated assets: the relationship ANCHOR is the asset's CONTROLLER
	// (the delegating identity — an organization or an individual), not the
	// per-asset AID, so the pairwise presented at login is the same constant AID
	// the controller enrolled (e.g. at sponsorship/add_employee). Empty → anchor
	// to SiteAID (the default per-RP unlinkability model).
	RelationshipAnchorAID  string `json:"relationship_anchor_aid,omitempty"`
	RelationshipAnchorOOBI string `json:"relationship_anchor_oobi,omitempty"`
	Sig                    string `json:"sig,omitempty"`
}

type RequestedCredential struct {
	SchemaSAID string `json:"schema_said"`
	Required   bool   `json:"required"`
}

// PresentedCredential is a held ACDC the signer presents in an assertion to
// satisfy a RequestedCredential. It carries the fields the relying party needs
// to authorize (schema + issuer + status) and the RAW ACDC bytes (base64) so the
// RP can cryptographically verify the SAID + issuer anchoring via the KERI driver.
// The presentation-signature fields (holder binding) are optional and filled when
// the signer produces a signed presentation.
type PresentedCredential struct {
	SAID        string `json:"said"`
	SchemaSAID  string `json:"schema_said"`
	IssuerAID   string `json:"issuer_aid"`
	HolderAID   string `json:"holder_aid"`
	Status      string `json:"status"`
	AcdcJsonB64 string `json:"acdc_json_b64"` // base64 of the ORIGINAL acdc_json (exact bytes for SAID)
	// Holder-binding presentation (optional; proves the presenter controls the holder AID).
	PresSaidB64     string `json:"pres_said_b64,omitempty"`
	CesrSig         string `json:"cesr_sig,omitempty"`
	HolderPublicKey string `json:"holder_public_key,omitempty"`
}

type RequestedScore struct {
	MinBand  string `json:"min_band,omitempty"`
	MinScore int    `json:"min_score,omitempty"`
	Required bool   `json:"required,omitempty"`
}

type Assertion struct {
	V                   string                 `json:"v"`
	T                   string                 `json:"t"`
	D                   string                 `json:"d,omitempty"`
	I                   string                 `json:"i"`
	RelationshipAIDOOBI string                 `json:"relationship_aid_oobi"`
	Audience            string                 `json:"audience"`
	Nonce               string                 `json:"nonce"`
	Dt                  string                 `json:"dt"`
	Disclosures         map[string]string      `json:"disclosures"`
	PresentedACDCs      []interface{}          `json:"presented_acdcs"`
	CustomData          map[string]interface{} `json:"custom_data,omitempty"`
	PKEL                string                 `json:"p_kel,omitempty"`
	Sig                 string                 `json:"sig,omitempty"`
}

type SiteRelationship struct {
	SiteAID     string `json:"site_aid"`
	PairwiseAID string `json:"pairwise_aid"`
	// SeedB64 kept for compat but not used for secrets (re-derive from root + RelationshipIndex)
	SeedB64           string `json:"seed_b64"`
	RelayOOBI         string `json:"relay_oobi"`
	DisplayName       string `json:"display_name,omitempty"`
	Email             string `json:"email,omitempty"`
	RelationshipIndex int    `json:"relationship_index,omitempty"` // stable index for HD derivation (do not hash AID)
}

type StartLoginRequest struct {
	SessionToken string `json:"session_token"`
	RPSessionURL string `json:"rp_session_url"`
}

type LoginPreviewResponse struct {
	Pending              bool              `json:"pending"`
	SessionToken         string            `json:"session_token"`
	SiteAID              string            `json:"site_aid"`
	SiteOOBI             string            `json:"site_oobi"`
	Audience             string            `json:"audience"`
	RequestedDisclosures []string          `json:"requested_disclosures"`
	DisclosurePreview    map[string]string `json:"disclosure_preview"`
	Expiry               string            `json:"expiry"`
	PairwiseAID          string            `json:"pairwise_aid,omitempty"`
	// Set when the login uses a controller-anchored membership relationship
	// (verified delegation) — lets consent UI say "sign in as a member" vs.
	// "use your account with this site".
	RelationshipAnchorAID string `json:"relationship_anchor_aid,omitempty"`
	RPSessionURL          string `json:"rp_session_url"`
}

// ScoreAttestation is a signed statement about the holder's identity level.
//
// The level is only meaningful alongside WHO is asserting it: a relying party
// deciding whether to trust "green" needs to know which provider said so and
// how they established it. An agent may be configured with any provider, so the
// envelope carries the issuer rather than the protocol assuming one.
type ScoreAttestation struct {
	RelationshipAID string `json:"relationship_aid"`
	// Issuer identifies the provider asserting the level — an AID where the
	// provider has one, otherwise a stable name. Empty means self-asserted.
	Issuer string `json:"issuer,omitempty"`
	// Method is how the level was established (e.g. "document_check",
	// "self_asserted"), free-form because providers differ.
	Method                 string `json:"method,omitempty"`
	Band                   string `json:"band"`
	Score                  int    `json:"score,omitempty"`
	ScoreAsOf              string `json:"score_as_of"`
	FreshnessWindowSeconds int    `json:"freshness_window_seconds"`
	Sig                    string `json:"sig,omitempty"`
}
