package server

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
)

// t = 4 -> sign_org. During organisation creation, an individual's PERSONAL Identity
// Agent scans the organisation's signer QR, signs a vouch over the org AID (the org's
// stored proof that a real person stands behind it), and becomes the org's FIRST
// employee with the super-admin role. There is no delegated inception — the org
// controls its own keys; the signer merely attests. Unlike add_employee (t=3),
// the signer is ACTIVE immediately (they're the founder — no one above them to
// approve) and provides the vouch signature.
type addSignerAsk struct{}

func (addSignerAsk) Action() string { return "sign_org" }

type signerPayload struct {
	OrgName     string `json:"org_name"`
	OrgAID      string `json:"org_aid"`
	OrgOOBI     string `json:"org_oobi"`
	SiteAID     string `json:"site_aid"` // the org identity the signer relates to (root during onboarding)
	SiteOOBI    string `json:"site_oobi"`
	InviteToken string `json:"invite_token"`
}

func (addSignerAsk) Preview(s *CoreServer, ctx AskContext) (GenericPreview, error) {
	var p signerPayload
	if err := json.Unmarshal(ctx.AskBytes, &p); err != nil || p.InviteToken == "" {
		return GenericPreview{}, fmt.Errorf("signer Ask missing invite_token")
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
		T: 4, Action: "sign_org", Title: "Sign an organization into existence",
		Subtitle:     "Signer " + org + " — you'll become its super-admin and first employee",
		Counterparty: p.OrgAID,
		Details:      details,
		Warning: "You are attesting that a real person (you) stands behind this organization. " +
			disclosureSummary(fields),
	}, nil
}

func (addSignerAsk) Execute(s *CoreServer, ctx AskContext, d ScanDecision) (map[string]interface{}, error) {
	if !d.Approved {
		return map[string]interface{}{"ok": true, "declined": true}, nil
	}
	var p signerPayload
	if err := json.Unmarshal(ctx.AskBytes, &p); err != nil || p.InviteToken == "" {
		return nil, fmt.Errorf("signer Ask missing invite_token")
	}
	if s.loginHandler == nil {
		return nil, fmt.Errorf("signer_org requires the login engine to derive the organisation relationship")
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

	// 3) Sign the vouch: our signature over {signer_aid, org_aid} with the pairwise
	//    key — the org stores this as proof a real person signered it.
	seed, serr := s.loginHandler.RelationshipSeed(rel)
	if serr != nil {
		return nil, fmt.Errorf("load relationship seed: %w", serr)
	}
	vouchPayload, _ := json.Marshal(map[string]string{
		"v": "VOUCH1", "action": "sign_org",
		"signer_aid": rel.PairwiseAID, "org_aid": p.OrgAID,
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
	// The key this owner will sign with, and the one they have already
	// committed to rotating to.
	//
	// WITHOUT THESE THE ORGANISATION REFUSES THE WHOLE REQUEST, and it is right
	// to: an organisation that recorded an owner whose signature it could not
	// check would have an owner in name only, and would find out the first time
	// that owner tried to do anything. The vouch proves a person stood behind
	// this organisation once; these are what let it recognise them ever again.
	//
	// The same relationship key that signed the vouch just above, so the
	// organisation verifies that signature against the key it was given rather
	// than against a second key that merely arrived alongside it.
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	nextSeed, nerr := s.nextRelationshipSeed(rel)
	if nerr != nil {
		return nil, fmt.Errorf("derive the rotation key this owner commits to: %w", nerr)
	}
	nextPub := ed25519.NewKeyFromSeed(nextSeed).Public().(ed25519.PublicKey)

	// What this organisation will seal its backups and its disk to.
	//
	// Derived here because this is the only moment the owner is present. An
	// organisation holds its own signing seed and the founder never sees it —
	// there is no phrase to write down — so an archive only the owner can open
	// is the one way an organisation survives losing the machine it runs on.
	// On rented hardware it is also the owner's only way back into an encrypted
	// disk whose other key moves with the software's measurement.
	//
	// Public halves only: they lock things TO this owner and open nothing.
	// Not fatal if the key cannot be derived — an organisation with an owner it
	// can verify and no recovery is a problem to fix, while refusing here would
	// leave one with no owner at all, which cannot be repaired later.
	sealKey := ""
	if keys, kerr := s.ownerBackupSealPublicKeys(); kerr == nil && len(keys) > 0 {
		sealKey = keys[0]
	} else if kerr != nil {
		log.Printf("[sign_org] signing for %s without a recovery key (%v) — this organisation "+
			"will not be able to write a backup anybody can restore", p.OrgAID, kerr)
	}

	body, _ := json.Marshal(disclosureBody(fields, profile, map[string]string{
		"pairwise_aid":               rel.PairwiseAID,
		"oobi":                       rel.RelayOOBI,
		"vouch_sig":                  vouchSig,
		"vouch_payload":              string(vouchPayload),
		"public_key":                 iacrypto.VerkeyQB64(pub),
		"next_public_key":            iacrypto.VerkeyQB64(nextPub),
		"backup_seal_public_key_b64": sealKey,
	}))
	redeemURL := strings.TrimRight(ctx.Base, "/") + "/api/signer/invites/" + p.InviteToken + "/redeem"
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(redeemURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("redeem signer invite: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		// Carry the org's explanation through (e.g. "signer invite already
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
		"status":       "active", // the signer is active immediately
	}, nil
}

// nextRelationshipSeed is the key this relationship has committed to rotating
// to — generation 1 of the same derivation that produced the current one.
//
// Pre-rotation is not optional in KERI: an inception commits to the NEXT key,
// and an owner recorded without one could never rotate, which for an
// organisation means its owner could never be replaced. That is the single
// thing the whole found-as-root shape exists to keep possible.
func (s *CoreServer) nextRelationshipSeed(rel *login.SiteRelationship) ([]byte, error) {
	if rel == nil || rel.RelationshipIndex <= 0 {
		return nil, fmt.Errorf("this relationship has no key index, so no rotation key can be derived from it")
	}
	root, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		return nil, fmt.Errorf("no root seed on this device: %w", err)
	}
	return backup.DerivePairwiseSeed(root, rel.RelationshipIndex, 1)
}
