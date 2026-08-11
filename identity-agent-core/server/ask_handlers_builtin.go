package server

import (
	"encoding/json"
	"fmt"
	"log"

	"identity-agent-core/login"
)

// Built-in Ask actions. Each new transaction type registers here.
func init() {
	registerAsk(1, loginAsk{})
	registerAsk(2, addContactAsk{})
	registerAsk(3, addEmployeeAsk{})
	registerAsk(4, addSignerAsk{})
}

// tierRank orders the escalation tiers so we only ever escalate, never downgrade.
func tierRank(c string) int {
	switch c {
	case "transactional":
		return 0
	case "general":
		return 1
	case "professional":
		return 2
	case "trusted":
		return 3
	default:
		return 0
	}
}

// ---- t=1: login (the RP asks you to prove who you are) ----

type loginAsk struct{}

func (loginAsk) Action() string { return "login" }

// AskAuth: login establishes the asker itself, and more strictly than the base
// layer could. verifyChallengeSig checks the challenge against the key the
// site's own address publishes, and where the challenge claims an anchor,
// verifyDelegationAnchor requires a delegated inception naming it.
func (loginAsk) AskAuth() askAuth { return authSelfVerifying }

func (loginAsk) Preview(s *CoreServer, ctx AskContext) (GenericPreview, error) {
	if s.loginHandler == nil {
		return GenericPreview{}, fmt.Errorf("login handler unavailable")
	}
	pv, err := s.loginHandler.Preview(login.StartLoginRequest{SessionToken: ctx.Token, RPSessionURL: ctx.Base})
	if err != nil {
		return GenericPreview{}, err
	}
	details := make([]PreviewDetail, 0, len(pv.RequestedDisclosures))
	for _, f := range pv.RequestedDisclosures {
		details = append(details, PreviewDetail{Label: f, Value: pv.DisclosurePreview[f]})
	}
	// A site can ask for credentials and a trust score as well as fields.
	// Listing only the fields and then saying "only the fields above will be
	// shared" understated what approving does.
	for _, rc := range pv.RequestedCredentials {
		details = append(details, PreviewDetail{
			Label: "Credential " + shortSAID(rc.SchemaSAID),
			Value: credentialRequestValue(rc),
		})
	}
	if pv.RequestedScore != nil {
		details = append(details, PreviewDetail{Label: "Trust score", Value: scoreRequestValue(pv.RequestedScore)})
	}
	return GenericPreview{
		T: 1, Action: "login", Title: "Sign-in request",
		Subtitle: pv.Audience, Counterparty: pv.SiteAID, Details: details,
		Warning: "Only what is listed above is shared.",
	}, nil
}

// credentialRequestValue says what approving would actually do about this
// credential — including that it would present nothing, which is the case a
// user needs to see before a site rejects them for it.
func credentialRequestValue(rc login.CredentialRequestPreview) string {
	switch {
	case rc.Held && rc.Required:
		return "required — will be presented"
	case rc.Held:
		return "optional — will be presented"
	case rc.Required:
		return "required — you hold none, sign-in may be refused"
	default:
		return "optional — you hold none, nothing presented"
	}
}

func scoreRequestValue(rs *login.RequestedScore) string {
	v := "your trust score is shared"
	switch {
	case rs.MinBand != "":
		v += " (site asks for band " + rs.MinBand + " or better)"
	case rs.MinScore > 0:
		v += fmt.Sprintf(" (site asks for %d or better)", rs.MinScore)
	}
	if rs.Required {
		v += " — required"
	}
	return v
}

// shortSAID keeps a schema identifier recognisable without filling the row.
func shortSAID(said string) string {
	if len(said) > 12 {
		return said[:12] + "…"
	}
	return said
}

func (loginAsk) Execute(s *CoreServer, ctx AskContext, d ScanDecision) (map[string]interface{}, error) {
	req := login.StartLoginRequest{SessionToken: ctx.Token, RPSessionURL: ctx.Base}
	if !d.Approved {
		s.loginHandler.Decline(req)
		return map[string]interface{}{"ok": true, "declined": true}, nil
	}
	res, err := s.loginHandler.Approve(req)
	if err != nil {
		return nil, err
	}
	// Foundational layer: logging in is a KERI interaction, so the site becomes (at least) a
	// transactional contact. Best-effort — never fail a successful login over this.
	if siteOOBI := jsonStringField(ctx.AskBytes, "site_oobi"); siteOOBI != "" {
		if _, _, cerr := s.EnsureKeriContact(siteOOBI); cerr != nil {
			log.Printf("[identity-agent-core] login: could not record site as transactional contact: %v", cerr)
		}
	}
	return res, nil
}

// ---- t=2: add-contact (a peer asks to become your contact) ----

type addContactAsk struct{}

func (addContactAsk) Action() string { return "add_contact" }

type addContactPayload struct {
	AskerAID   string `json:"asker_aid"`
	AskerOOBI  string `json:"asker_oobi"`
	AskerAlias string `json:"asker_alias"`
}

func (addContactAsk) Preview(s *CoreServer, ctx AskContext) (GenericPreview, error) {
	var p addContactPayload
	_ = json.Unmarshal(ctx.AskBytes, &p)
	if p.AskerOOBI == "" {
		return GenericPreview{}, fmt.Errorf("add-contact Ask missing asker_oobi")
	}
	name := p.AskerAlias
	if name == "" {
		name = p.AskerAID
	}
	// Accepting sends our details back — show exactly which ones, from the
	// action's own declaration, so the consent screen and the payload cannot
	// disagree.
	fields, err := declaredDisclosure(2)
	if err != nil {
		return GenericPreview{}, err
	}
	profile, _ := s.DataStore.GetProfile()
	return GenericPreview{
		T: 2, Action: "add_contact", Title: "Contact request",
		Subtitle: name + " wants to be your contact", Counterparty: p.AskerAID,
		Details:     disclosureRows(fields, profile),
		TierOptions: []string{"general", "trusted", "professional"}, DefaultTier: "general",
		Warning: disclosureSummary(fields),
	}, nil
}

func (addContactAsk) Execute(s *CoreServer, ctx AskContext, d ScanDecision) (map[string]interface{}, error) {
	if !d.Approved {
		return map[string]interface{}{"ok": true, "declined": true}, nil
	}
	var p addContactPayload
	if err := json.Unmarshal(ctx.AskBytes, &p); err != nil || p.AskerOOBI == "" {
		return nil, fmt.Errorf("add-contact Ask missing asker_oobi")
	}
	// Foundational layer establishes the baseline transactional/keri contact.
	contact, _, err := s.EnsureKeriContact(p.AskerOOBI)
	if err != nil {
		return nil, err
	}
	// Escalate to the chosen tier (default general), never downgrade.
	tier := d.Tier
	if tier == "" {
		tier = "general"
	}
	if tierRank(tier) > tierRank(contact.ContactCategory) {
		contact.ContactCategory = tier
		if serr := s.DataStore.SaveContact(*contact); serr != nil {
			return nil, serr
		}
	}
	// Tell the asker we accepted, so they record us too (best-effort).
	go s.sendIntroduction(contact.AID, p.AskerOOBI, 2)
	return map[string]interface{}{"ok": true, "contact_aid": contact.AID, "tier": contact.ContactCategory}, nil
}

// sendIntroduction tells a peer who we are, inside the envelope.
//
// What we send about ourselves comes from the action's `discloses` declaration
// — the same list the consent screen showed — not from whatever the profile
// happens to hold.
//
// It carries no claim about who sent it. That is what the envelope establishes,
// and a field saying so would be a field somebody could fill in. It also needs
// no signature of its own: signing as the identity requires a key the agent
// does not hold, which is why this went out unsigned and was refused when it
// was its own plaintext request.
func (s *CoreServer) sendIntroduction(aid, oobiURL string, actionCode int) {
	ourIdentity, err := s.DataStore.GetIdentity()
	if err != nil || ourIdentity == nil {
		return
	}
	publicURL := s.EndpointService.CurrentURL()
	if publicURL == "" {
		return
	}
	fields, derr := declaredDisclosure(actionCode)
	if derr != nil {
		log.Printf("[identity-agent-core] introduction: refusing to send, %v", derr)
		return
	}
	ourOOBI := fmt.Sprintf("%s/public/oobi/%s", publicURL, ourIdentity.AID)
	ourAlias := ourIdentity.AID
	if len(ourAlias) >= 12 {
		ourAlias = ourAlias[:12] + "..."
	}
	profile, _ := s.DataStore.GetProfile()
	jcard, photo := buildDisclosure(fields, profile, ourIdentity.AID, ourOOBI)
	if jcard.FullName != "" {
		ourAlias = jcard.FullName
	}
	payload := map[string]interface{}{
		"alias":    ourAlias,
		"oobi_url": ourOOBI,
		"jcard":    jcard,
	}
	if photo != "" {
		payload["photo"] = photo
	}
	if err := s.introduceOurselvesTo(aid, oobiURL, payload); err != nil {
		log.Printf("[introduction] could not tell %s who we are: %v", aid, err)
	}
}

// jsonStringField pulls a top-level string field out of raw JSON without a full struct.
func jsonStringField(raw []byte, field string) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	var v string
	if r, ok := m[field]; ok {
		_ = json.Unmarshal(r, &v)
	}
	return v
}
