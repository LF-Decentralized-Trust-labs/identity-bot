package server

import (
	"encoding/json"
	"io"
	"fmt"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/login"
)

// t = 4 -> sponsor_org. During org creation, an individual's PERSONAL Identity
// Agent scans the org's sponsor QR, signs a vouch over the org AID (the org's
// stored proof that a real person stands behind it), and becomes the org's FIRST
// employee with the super-admin role. There is no delegated inception — the org
// controls its own keys; the sponsor merely attests. Unlike add_employee (t=3),
// the sponsor is ACTIVE immediately (they're the founder — no one above them to
// approve) and provides the vouch signature.
type addSponsorAsk struct{}

func (addSponsorAsk) Action() string { return "sponsor_org" }

type sponsorPayload struct {
	OrgName     string `json:"org_name"`
	OrgAID      string `json:"org_aid"`
	OrgOOBI     string `json:"org_oobi"`
	SiteAID     string `json:"site_aid"`  // the org identity the sponsor relates to (root during onboarding)
	SiteOOBI    string `json:"site_oobi"`
	InviteToken string `json:"invite_token"`
}

func (addSponsorAsk) Preview(s *CoreServer, ctx AskContext) (GenericPreview, error) {
	var p sponsorPayload
	if err := json.Unmarshal(ctx.AskBytes, &p); err != nil || p.InviteToken == "" {
		return GenericPreview{}, fmt.Errorf("sponsor Ask missing invite_token")
	}
	org := p.OrgName
	if org == "" {
		org = p.OrgAID
	}
	fields, ferr := declaredDisclosure(4)
	if ferr != nil {
		return GenericPreview{}, ferr
	}
	profile, _ := s.DataStore.GetProfile()
	details := []PreviewDetail{
		{Label: "Organization", Value: org},
		{Label: "Your role", Value: "Super Admin"},
	}
	details = append(details, disclosureRows(fields, profile)...)
	return GenericPreview{
		T: 4, Action: "sponsor_org", Title: "Sponsor an organization",
		Subtitle: "Sponsor " + org + " — you'll become its super-admin and first employee",
		Counterparty: p.OrgAID,
		Details: details,
		Warning: "You are attesting that a real person (you) stands behind this organization. " +
			disclosureSummary(fields),
	}, nil
}

func (addSponsorAsk) Execute(s *CoreServer, ctx AskContext, d ScanDecision) (map[string]interface{}, error) {
	if !d.Approved {
		return map[string]interface{}{"ok": true, "declined": true}, nil
	}
	var p sponsorPayload
	if err := json.Unmarshal(ctx.AskBytes, &p); err != nil || p.InviteToken == "" {
		return nil, fmt.Errorf("sponsor Ask missing invite_token")
	}
	if s.loginHandler == nil {
		return nil, fmt.Errorf("sponsor_org requires the login engine to derive the org relationship")
	}

	// 1) Establish the org as a professional-tier contact (hardwired, no ceremony).
	if p.OrgOOBI != "" {
		if contact, _, cerr := s.EnsureKeriContact(p.OrgOOBI); cerr == nil && contact != nil {
			if tierRank("professional") > tierRank(contact.ContactCategory) {
				contact.ContactCategory = "professional"
				_ = s.DataStore.SaveContact(*contact)
			}
		}
	}

	// 2) Derive our stable pairwise AID for the org.
	rel, rerr := s.loginHandler.GetOrCreateRelationship(p.SiteAID, &login.ChallengeBundle{SiteAID: p.SiteAID, SiteOOBI: p.SiteOOBI})
	if rerr != nil || rel == nil || rel.PairwiseAID == "" {
		return nil, fmt.Errorf("derive org relationship: %w", rerr)
	}

	// 3) Sign the vouch: our signature over {sponsor_aid, org_aid} with the pairwise
	//    key — the org stores this as proof a real person sponsored it.
	seed, serr := s.loginHandler.RelationshipSeed(rel)
	if serr != nil {
		return nil, fmt.Errorf("load relationship seed: %w", serr)
	}
	vouchPayload, _ := json.Marshal(map[string]string{
		"v": "VOUCH1", "action": "sponsor_org",
		"sponsor_aid": rel.PairwiseAID, "org_aid": p.OrgAID,
	})
	vouchSig, sigErr := login.SignAsk(vouchPayload, seed)
	if sigErr != nil {
		return nil, fmt.Errorf("sign vouch: %w", sigErr)
	}

	// 4) Redeem at the org: hand over our AID, OOBI, the vouch, and exactly the
	//    profile fields this action declares — the same ones the consent screen
	//    listed. The org verifies + stores the vouch and makes us an active
	//    super-admin employee.
	fields, ferr := declaredDisclosure(4)
	if ferr != nil {
		return nil, ferr
	}
	profile, _ := s.DataStore.GetProfile()
	body, _ := json.Marshal(disclosureBody(fields, profile, map[string]string{
		"pairwise_aid":  rel.PairwiseAID,
		"oobi":          rel.RelayOOBI,
		"vouch_sig":     vouchSig,
		"vouch_payload": string(vouchPayload),
	}))
	redeemURL := strings.TrimRight(ctx.Base, "/") + "/api/sponsor/invites/" + p.InviteToken + "/redeem"
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(redeemURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("redeem sponsor invite: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		// Carry the org's explanation through (e.g. "sponsor invite already
		// used") so the person sees a real reason, not a status code.
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		reason := strings.TrimSpace(string(msg))
		if reason == "" {
			reason = fmt.Sprintf("status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("the organization declined: %s", reason)
	}

	org := p.OrgName
	if org == "" {
		org = p.OrgAID
	}
	return map[string]interface{}{
		"ok":           true,
		"employer":     org,
		"role":         "Super Admin",
		"pairwise_aid": rel.PairwiseAID,
		"status":       "active", // the sponsor is active immediately
	}, nil
}
