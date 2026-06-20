package login

// ChallengeBundle is the login Ask (SEAM-8 §2 / SM10): v="ASK1", t=1 (login
// intent). The IA fetches it from the minimal QR pointer (/i/{token}) and
// verifies its signature against the site KEL before showing consent.
type ChallengeBundle struct {
	V                    string                 `json:"v"`
	T                    int                    `json:"t"`
	SiteAID              string                 `json:"site_aid"`
	SiteOOBI             string                 `json:"site_oobi"`
	Audience             string                 `json:"audience"`
	Nonce                string                 `json:"nonce"`
	Dt                   string                 `json:"dt"`
	Expiry               string                 `json:"expiry"`
	RequestedDisclosures []string               `json:"requested_disclosures"`
	RequestedCredentials []RequestedCredential  `json:"requested_credentials"`
	RequestedScore       *RequestedScore        `json:"requested_score,omitempty"`
	CallbackURL          string                 `json:"callback_url"`
	SessionToken         string                 `json:"session_token"`
	Sig                  string                 `json:"sig,omitempty"`
}

type RequestedCredential struct {
	SchemaSAID string `json:"schema_said"`
	Required   bool   `json:"required"`
}

type RequestedScore struct {
	MinBand   string `json:"min_band,omitempty"`
	MinScore  int    `json:"min_score,omitempty"`
	Required  bool   `json:"required,omitempty"`
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
	SiteAID    string `json:"site_aid"`
	PairwiseAID string `json:"pairwise_aid"`
	SeedB64    string `json:"seed_b64"`
	RelayOOBI  string `json:"relay_oobi"`
	DisplayName string `json:"display_name,omitempty"`
	Email      string `json:"email,omitempty"`
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
	RPSessionURL         string            `json:"rp_session_url"`
}

type ScoreAttestation struct {
	RelationshipAID          string `json:"relationship_aid"`
	Band                     string `json:"band"`
	Score                    int    `json:"score,omitempty"`
	ScoreAsOf                string `json:"score_as_of"`
	FreshnessWindowSeconds   int    `json:"freshness_window_seconds"`
	Sig                      string `json:"sig,omitempty"`
}