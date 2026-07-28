package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/login"
)

// t = 3 -> add_employee. An organization invites an individual to join as an
// employee. Unlike login (minted by the RP website) and add_contact (a symmetric
// peer ceremony), this is minted by the ORG and carries the target portal so the
// accepting individual derives their STABLE per-site pairwise AID against it — the
// same AID they later present at that portal's login. Approval enrolls that AID in
// the org's active-employee list; the portal's membership gate (MembershipSource ==
// "employees") then recognizes the employee by AID alone. No credential (AID
// method); the credential path stays available as the additive second gate.
type addEmployeeAsk struct{}

func (addEmployeeAsk) Action() string { return "add_employee" }

type addEmployeePayload struct {
	OrgName     string `json:"org_name"`
	OrgAID      string `json:"org_aid"`
	OrgOOBI     string `json:"org_oobi"`
	SiteAID     string `json:"site_aid"`
	SiteOOBI    string `json:"site_oobi"`
	Role        string `json:"role"`
	InviteToken string `json:"invite_token"`
}

func (addEmployeeAsk) Preview(s *CoreServer, ctx AskContext) (GenericPreview, error) {
	var p addEmployeePayload
	if err := json.Unmarshal(ctx.AskBytes, &p); err != nil || p.InviteToken == "" {
		return GenericPreview{}, fmt.Errorf("add-employee Ask missing invite_token")
	}
	org := p.OrgName
	if org == "" {
		org = p.OrgAID
	}
	sub := "Join " + org + " as an employee"
	if p.Role != "" {
		sub = "Join " + org + " as " + p.Role
	}
	// Joining hands the org details about you — show which, from the action's
	// own declaration, so the screen and the redeem body cannot disagree.
	fields, ferr := declaredDisclosure(3)
	if ferr != nil {
		return GenericPreview{}, ferr
	}
	profile, _ := s.DataStore.GetProfile()
	details := []PreviewDetail{
		{Label: "Organization", Value: org},
		{Label: "Role", Value: p.Role},
	}
	details = append(details, disclosureRows(fields, profile)...)
	return GenericPreview{
		T: 3, Action: "add_employee", Title: "Employment invitation",
		Subtitle: sub, Counterparty: p.OrgAID,
		Details: details,
		Warning: disclosureSummary(fields),
	}, nil
}

func (addEmployeeAsk) Execute(s *CoreServer, ctx AskContext, d ScanDecision) (map[string]interface{}, error) {
	if !d.Approved {
		return map[string]interface{}{"ok": true, "declined": true}, nil
	}
	var p addEmployeePayload
	if err := json.Unmarshal(ctx.AskBytes, &p); err != nil || p.InviteToken == "" {
		return nil, fmt.Errorf("add-employee Ask missing invite_token")
	}
	if s.loginHandler == nil {
		return nil, fmt.Errorf("add_employee requires the login engine (desktop) to derive the portal relationship")
	}

	// 1) Hardwire the org as a contact (professional tier) WITHOUT the add_contact
	//    ceremony — accepting an employment invite is itself the explicit, mutual act.
	if p.OrgOOBI != "" {
		if contact, _, cerr := s.EnsureKeriContact(p.OrgOOBI); cerr == nil && contact != nil {
			if tierRank("professional") > tierRank(contact.ContactCategory) {
				contact.ContactCategory = "professional"
				_ = s.DataStore.SaveContact(*contact)
			}
		}
	}

	// 2) Derive our STABLE pairwise AID for the ORG — your "employee number".
	//    Anchoring on the org (not any one portal asset) means the same AID works
	//    on every asset the org delegates, now or later, with zero re-enrollment;
	//    login reuses it via the challenge's relationship anchor (also the org).
	//    This is the same anchor the sponsor flow uses, so sponsor + employee
	//    rows in the org roster are one consistent identifier space. Falls back
	//    to the site AID only for legacy invites that carry no org identity.
	anchorAID, anchorOOBI := p.OrgAID, p.OrgOOBI
	if anchorAID == "" {
		anchorAID, anchorOOBI = p.SiteAID, p.SiteOOBI
	}
	rel, rerr := s.loginHandler.GetOrCreateRelationship(anchorAID, &login.ChallengeBundle{SiteAID: anchorAID, SiteOOBI: anchorOOBI})
	if rerr != nil || rel == nil || rel.PairwiseAID == "" {
		return nil, fmt.Errorf("derive org relationship: %w", rerr)
	}

	// 3) Redeem at the org: hand them our pairwise AID plus exactly the profile
	//    fields this action declares — the same ones the consent screen listed —
	//    so the roster can show a real person without us volunteering more.
	fields, ferr := declaredDisclosure(3)
	if ferr != nil {
		return nil, ferr
	}
	profile, _ := s.DataStore.GetProfile()
	body, _ := json.Marshal(disclosureBody(fields, profile, map[string]string{
		"pairwise_aid": rel.PairwiseAID,
		"oobi":         rel.RelayOOBI,
	}))
	redeemURL := strings.TrimRight(ctx.Base, "/") + "/api/employees/invites/" + p.InviteToken + "/redeem"
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(redeemURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("redeem employee invite: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		// Carry the org's explanation through (e.g. "employee invite already
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
		"role":         p.Role,
		"pairwise_aid": rel.PairwiseAID,
		"status":       "pending", // the org must approve before access is granted
	}, nil
}
