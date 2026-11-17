package server

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/binding"
	"identity-agent-core/enrolsecret"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"

	"github.com/go-chi/chi/v5"
)

// A person joins two of their identifiers to one record by one statement signed
// with both keys (ADR-082). This file has both sides: the organisation's, which
// mints the invite and checks the statement, and the person's, the Ask (t=7)
// that asks them and signs.

// ActionBindSite is the action code of "Join a site with one identity"
// (actions/registry.json).
const ActionBindSite = 7

// ---- the person's side: t=7, bind_site ----

type bindSiteAsk struct{}

func (bindSiteAsk) Action() string { return "bind_site" }

type bindSitePayload struct {
	OrgName       string `json:"org_name"`
	OrgAID        string `json:"org_aid"`
	OrgOOBI       string `json:"org_oobi"`
	SiteAID       string `json:"site_aid"`
	SiteOOBI      string `json:"site_oobi"`
	SiteName      string `json:"site_name"`
	RecordSiteAID string `json:"record_site_aid"`
	// RecordSiteOOBI is where the log of the record's site is introduced.
	RecordSiteOOBI string `json:"record_site_oobi"`
	Role           string `json:"role"`
	InviteToken    string `json:"invite_token"`
	// RedeemURL is where the statement goes. It is the organisation's own word (it is inside
	// OrgSig), so a host that merely served the Ask cannot choose it.
	RedeemURL string `json:"redeem_url"`
	// OrgSig is the organisation's signature, with the key its own key log shows is current,
	// over the Ask as it was before the base-layer signature and this one were added.
	OrgSig string `json:"org_sig"`
}

func (p bindSitePayload) read(ctx AskContext) (bindSitePayload, error) {
	if err := json.Unmarshal(ctx.AskBytes, &p); err != nil || p.InviteToken == "" || p.OrgAID == "" ||
		p.SiteAID == "" || p.RecordSiteAID == "" {
		return p, errors.New("the request to join a site is missing what it needs")
	}
	if p.Role != binding.RolePerson && p.Role != binding.RoleOwner {
		return p, errors.New("the request to join a site names neither a person nor the owner")
	}
	if p.SiteAID == p.RecordSiteAID {
		return p, errors.New("the request to join a site names one identifier twice")
	}
	return p, nil
}

func (bindSiteAsk) Preview(s *CoreServer, ctx AskContext) (GenericPreview, error) {
	p, err := bindSitePayload{}.read(ctx)
	if err != nil {
		return GenericPreview{}, err
	}
	if s.loginHandler == nil {
		return GenericPreview{}, errors.New("joining a site needs the login engine to derive the relationship")
	}
	// The organisation's signature and both sites are checked before anything this person
	// holds is looked at. The checks fetch addresses the Ask chose, so checking what the
	// person holds first would let whoever wrote an Ask learn, from whether those fetches
	// came, whether the person holds an identifier at a place.
	if err := s.theOrganisationAsked(ctx.AskBytes, p); err != nil {
		return GenericPreview{}, err
	}
	if err := s.bothSitesAreTheOrganisations(p); err != nil {
		return GenericPreview{}, err
	}
	// Refused before it is shown: a person cannot be asked to join an identifier
	// they do not hold, and asking would only invite an approval that signs nothing.
	if _, ok := s.loginHandler.Store.Get(p.RecordSiteAID); !ok {
		return GenericPreview{}, errors.New("you have no identifier at the place this joins you from, so there is nothing to join this to")
	}
	org := firstOf(p.OrgName, p.OrgAID)
	site := firstOf(p.SiteName, p.SiteAID)
	return GenericPreview{
		T: ActionBindSite, Action: "bind_site", Title: "Join " + site,
		Subtitle: org + " asks you to join " + site + " as the same person you are to them", Counterparty: p.OrgAID,
		Details: []PreviewDetail{{Label: "Organization", Value: org}, {Label: "Site", Value: site}, {Label: "Joining as", Value: roleWords(p.Role)}},
		Warning: org + " will know that you here and you where you already deal with them are the same person, and will keep a statement you signed that proves it to anyone it shows it to. This cannot be undone except by leaving.",
	}, nil
}

// keyOfOrganisation is the organisation's current signing key, read from its own key log
// (the log must validate and derive the identifier), never from the host that served the Ask.
func (s *CoreServer) keyOfOrganisation(oobi, aid string) ([]byte, error) {
	if s.organisationKeyOf != nil {
		return s.organisationKeyOf(oobi, aid)
	}
	if oobi == "" {
		return nil, errors.New("the request names no introduction for the organization")
	}
	return login.KeyFromOOBI(s.peerClient(15*time.Second, oobi), oobi, aid)
}

// theOrganisationAsked refuses an Ask the organisation it names did not sign, and one whose
// redeem address is not the one it signed for this invite. Without it anybody could serve an Ask
// naming a real organisation and its real sites and collect the person's statement, which proves two of
// their identifiers are one person to a party they never agreed to tell.
func (s *CoreServer) theOrganisationAsked(ask []byte, p bindSitePayload) error {
	if p.OrgSig == "" {
		return errors.New("this request is not signed by the organization it names, so it may not be from it")
	}
	key, err := s.keyOfOrganisation(p.OrgOOBI, p.OrgAID)
	if err != nil {
		return fmt.Errorf("the organization's own key could not be established: %w", err)
	}
	form := binding.NewInvite(p.OrgAID, p.OrgName, p.SiteAID, p.SiteName, p.RecordSiteAID, p.Role, enrolsecret.Digest(p.InviteToken), p.RedeemURL)
	if err := binding.VerifyInvite(form, p.OrgSig, key); err != nil {
		return err
	}
	u, err := url.Parse(p.RedeemURL)
	if err != nil || u.Host == "" || !strings.HasSuffix(u.Path, "/api/binding/invites/"+p.InviteToken+"/redeem") {
		return errors.New("the request does not say where the organization takes the statement")
	}
	// The statement and both key logs are not sent in the clear, unless this owner has said local sites are fine.
	if u.Scheme != "https" && os.Getenv("IA_ALLOW_LOCAL_SITES") != "1" {
		return errors.New("the organization takes the statement at an address that is not https")
	}
	return nil
}

// bothSitesAreTheOrganisations refuses a request that names, as the organisation's, an identifier
// that is not. Without it an organisation could name any site the person holds an identifier at
// as the place the record's identifier is from, and the statement would hand that identifier to it.
func (s *CoreServer) bothSitesAreTheOrganisations(p bindSitePayload) error {
	check := s.siteIsDelegatedBy
	if check == nil {
		check = s.loginHandler.SiteIsDelegatedBy
	}
	if err := check(p.RecordSiteAID, p.RecordSiteOOBI, p.OrgAID, p.OrgOOBI); err != nil {
		return fmt.Errorf("the place this joins you from is not one this organization runs: %w", err)
	}
	if err := check(p.SiteAID, p.SiteOOBI, p.OrgAID, p.OrgOOBI); err != nil {
		return fmt.Errorf("the site is not one this organization runs: %w", err)
	}
	return nil
}

func roleWords(role string) string {
	if role == binding.RoleOwner {
		return "the owner of the organization"
	}
	return "a person"
}

func firstOf(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (bindSiteAsk) Execute(s *CoreServer, ctx AskContext, d ScanDecision) (map[string]interface{}, error) {
	// "Not now" signs nothing, and says nothing to anyone.
	if !d.Approved {
		return map[string]interface{}{"ok": true, "declined": true}, nil
	}
	p, err := bindSitePayload{}.read(ctx)
	if err != nil {
		return nil, err
	}
	if s.loginHandler == nil {
		return nil, errors.New("joining a site needs the login engine to derive the relationship")
	}
	if err := s.theOrganisationAsked(ctx.AskBytes, p); err != nil {
		return nil, err
	}
	if err := s.bothSitesAreTheOrganisations(p); err != nil {
		return nil, err
	}
	// The record's identifier must be one this person already holds. It is looked up
	// and never made: making one would sign for an identifier nobody had.
	recRel, ok := s.loginHandler.Store.Get(p.RecordSiteAID)
	if !ok || recRel.PairwiseAID == "" {
		return nil, errors.New("you have no identifier at the place this joins you from")
	}
	// An identifier made here for the site is kept only if the organisation takes the
	// statement: a refusal, or a statement that never arrived, leaves the person as they were.
	_, hadOne := s.loginHandler.Store.Get(p.SiteAID)
	newRel, rerr := s.loginHandler.GetOrCreateRelationship(p.SiteAID, &login.ChallengeBundle{SiteAID: p.SiteAID, SiteOOBI: p.SiteOOBI})
	if rerr != nil || newRel == nil || newRel.PairwiseAID == "" {
		return nil, fmt.Errorf("derive the identifier for the site: %w", rerr)
	}
	taken := false
	if !hadOne {
		defer func() {
			if !taken {
				_ = s.loginHandler.Store.Delete(p.SiteAID)
			}
		}()
	}
	recSeed, err := s.loginHandler.RelationshipSeed(&recRel)
	if err != nil {
		return nil, fmt.Errorf("load the key of the identifier being joined to: %w", err)
	}
	newSeed, err := s.loginHandler.RelationshipSeed(newRel)
	if err != nil {
		return nil, fmt.Errorf("load the key of the new identifier: %w", err)
	}
	link, err := binding.Sign(binding.Statement{
		V: binding.Version, Org: p.OrgAID, Site: p.SiteAID, Record: recRel.PairwiseAID, New: newRel.PairwiseAID,
		Invite: enrolsecret.Digest(p.InviteToken), Role: p.Role,
	}, recSeed, newSeed)
	if err != nil {
		return nil, err
	}
	recLog, err := s.loginHandler.RelationshipKeyLog(&recRel, recSeed)
	if err != nil {
		return nil, err
	}
	newLog, err := s.loginHandler.RelationshipKeyLog(newRel, newSeed)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(bindingRedeem{Link: link, RecordKeyLog: recLog, NewKeyLog: newLog})
	// To where the organisation said, never to the host that served the Ask.
	redeemURL := p.RedeemURL
	resp, err := siteClient(15*time.Second, redeemURL).Post(redeemURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("send the statement: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return nil, fmt.Errorf("the organization declined: %s", strings.TrimSpace(string(msg)))
	}
	taken = true
	// Kept only once the organisation has taken it: a joining the organisation never
	// recorded is not one the person should be shown as made.
	newRel.Bound = &login.BoundRecord{OrgAID: p.OrgAID, Role: p.Role, RecordIdentifier: recRel.PairwiseAID, At: time.Now().UTC().Format(time.RFC3339)}
	if err := s.loginHandler.Store.Put(*newRel); err != nil {
		return nil, fmt.Errorf("the organization recorded it, but it could not be kept here: %w", err)
	}
	return map[string]interface{}{"ok": true, "bound": true, "role": p.Role}, nil
}

// handleListWhatIJoined is the list a person's Identity Agent serves: every joining
// it signed, naming the organisation, the role and the two identifiers. Owner only.
func (s *CoreServer) handleListWhatIJoined(w http.ResponseWriter, r *http.Request) {
	if s.loginHandler == nil {
		writeJSON(w, map[string]any{"joined": []any{}})
		return
	}
	type row struct {
		Org    string `json:"org"`
		Role   string `json:"role"`
		Record string `json:"record_identifier"`
		New    string `json:"identifier"`
		Site   string `json:"site"`
		Bound  string `json:"at"`
	}
	rows := []row{}
	for _, rel := range s.loginHandler.Store.All() {
		if rel.Bound != nil {
			rows = append(rows, row{rel.Bound.OrgAID, rel.Bound.Role, rel.Bound.RecordIdentifier, rel.PairwiseAID, rel.SiteAID, rel.Bound.At})
		}
	}
	slices.SortFunc(rows, func(a, b row) int { return strings.Compare(a.Bound+a.New, b.Bound+b.New) })
	writeJSON(w, map[string]any{"joined": rows})
}

// ---- the organisation's side ----

type bindingRedeem struct {
	Link         binding.Link `json:"link"`
	RecordKeyLog string       `json:"record_key_log"`
	NewKeyLog    string       `json:"new_key_log"`
}

func (s *CoreServer) mountBindingRoutes(r chi.Router) {
	// The list a person's Identity Agent serves is theirs, and they hold no organisation's store.
	r.Get("/login/joined", s.handleListWhatIJoined)
	if s.assetHandler == nil {
		return
	}
	r.Route("/binding", func(r chi.Router) {
		// Owner only: nobody else may ask a person to join a site.
		r.Post("/invites", s.handleCreateBindingInvite)
		r.Get("/links", s.handleListBindings)
		// Public: the person's own Identity Agent redeems here (t=7). The invite is
		// single use, and what it takes is a statement only the person's two keys can make.
		r.Post("/invites/{token}/redeem", s.handleRedeemBindingInvite)
	})
}

type bindingInviteRequest struct {
	SiteAID           string   `json:"site_aid"`
	SiteOOBI          string   `json:"site_oobi"`
	SiteName          string   `json:"site_name"`
	RecordSiteAID     string   `json:"record_site_aid"`
	RecordSiteOOBI    string   `json:"record_site_oobi"`
	RecordIdentifiers []string `json:"record_identifiers"`
	Role              string   `json:"role"`
	// ExpiresInHours is how long the invite is accepted: 1 to 720 hours, 168 (a week) when left out.
	ExpiresInHours int `json:"expires_in_hours"`
}

const (
	bindingInviteHours        = 168
	bindingInviteLongestHours = 720
)

// handleCreateBindingInvite mints a single-use invite and its Ask (t=7).
//
// For a person it names the identifiers the record already holds, and one of them must
// sign. For the owner it names the owner the organisation's identity settled on, and
// only that: an owner the organisation cannot name by a key of its own (an organisation
// that is its own authority, which is the local case) is refused, because the organisation
// cannot assert an identifier it cannot check a key of.
func (s *CoreServer) handleCreateBindingInvite(w http.ResponseWriter, r *http.Request) {
	var req bindingInviteRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "the request could not be read", http.StatusBadRequest)
		return
	}
	id, _ := s.DataStore.GetIdentity()
	if id == nil || id.AID == "" {
		http.Error(w, "this organisation has no identity yet to ask in", http.StatusConflict)
		return
	}
	if req.SiteAID == "" || req.RecordSiteAID == "" || req.SiteAID == req.RecordSiteAID {
		http.Error(w, "name the site, and the place the record's identifier is from, which are two places", http.StatusBadRequest)
		return
	}
	switch req.Role {
	case binding.RolePerson:
		if len(req.RecordIdentifiers) == 0 || len(req.RecordIdentifiers) > 32 || slices.Contains(req.RecordIdentifiers, "") {
			http.Error(w, "name the identifiers the record holds", http.StatusBadRequest)
			return
		}
	case binding.RoleOwner:
		oa, err := s.ownerAuthority()
		if err != nil || oa == nil || oa.AID == "" || oa.AID == id.AID || oa.PublicKey == "" {
			http.Error(w, "this organisation's owner is not an identifier of their own that it can check a key of, so the owner cannot join a site this way", http.StatusConflict)
			return
		}
		req.RecordIdentifiers = []string{oa.AID}
	default:
		http.Error(w, "an invite is for a person or the owner", http.StatusBadRequest)
		return
	}
	hours := req.ExpiresInHours
	if hours == 0 {
		hours = bindingInviteHours
	}
	if hours < 1 || hours > bindingInviteLongestHours {
		http.Error(w, fmt.Sprintf("an invite is accepted for 1 to %d hours", bindingInviteLongestHours), http.StatusBadRequest)
		return
	}
	publicURL := s.EndpointService.CurrentURL()
	if publicURL == "" {
		publicURL = s.getPublicURL(r)
	}
	orgName := ""
	if prof, _ := s.DataStore.GetProfile(); prof != nil {
		orgName = firstOf(prof.OrgName, prof.FullName)
	}
	// Everything that can fail is done before the invite is kept, so a refusal leaves no invite behind.
	inv := asset.EmployeeInvite{
		Token: genInviteToken(), Purpose: asset.PurposeBinding, BindRole: req.Role, MaxUses: 1,
		SiteAID: req.SiteAID, SiteOOBI: req.SiteOOBI, RecordIdentifiers: req.RecordIdentifiers,
		CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Duration(hours) * time.Hour).Truncate(time.Second),
	}
	orgSeed, oerr := s.identitySigningSeed()
	if oerr != nil {
		http.Error(w, "this organization's identity key is not held here, so it cannot sign an invite from here: "+oerr.Error(), http.StatusConflict)
		return
	}
	_, signerOOBI, seed, err := s.mintPairwise("binding")
	if err != nil {
		if refuseIfRootSeedRefused(w, err) {
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redeemURL := publicURL + "/api/binding/invites/" + inv.Token + "/redeem"
	// The organisation signs with its own identity key first, so a person's Identity Agent can tell the
	// Ask is its own and where it takes the statement; the pairwise key then signs the whole, as for any Ask.
	orgSig, oerr := binding.SignInvite(binding.NewInvite(id.AID, orgName, req.SiteAID, req.SiteName, req.RecordSiteAID, req.Role,
		enrolsecret.Digest(inv.Token), redeemURL), orgSeed)
	if oerr != nil {
		http.Error(w, "the invite could not be signed: "+oerr.Error(), http.StatusBadRequest)
		return
	}
	ask, err := json.Marshal(map[string]interface{}{
		"v": "ASK1", "t": ActionBindSite, "org_name": orgName, "org_aid": id.AID,
		"org_oobi": fmt.Sprintf("%s/public/oobi/%s", publicURL, id.AID),
		"site_aid": req.SiteAID, "site_oobi": req.SiteOOBI, "site_name": req.SiteName,
		"record_site_aid": req.RecordSiteAID, "record_site_oobi": req.RecordSiteOOBI, "role": req.Role, "invite_token": inv.Token,
		"signer_oobi": signerOOBI, "redeem_url": redeemURL, "org_sig": orgSig,
		// The Ask's own expiry, which the scan gate checks for every Ask: the person is not asked
		// about an invite the organisation will no longer take. The organisation's refusal at
		// redeem is what holds; this is not inside org_sig.
		"expiry": inv.ExpiresAt.Format(time.RFC3339),
	})
	if err != nil {
		http.Error(w, "the invite could not be written: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sig, serr := login.SignAsk(ask, seed)
	if serr != nil {
		http.Error(w, serr.Error(), http.StatusInternalServerError)
		return
	}
	ask, err = injectSig(ask, sig)
	if err != nil {
		http.Error(w, "the invite could not be signed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tb := make([]byte, 16)
	if _, rerr := rand.Read(tb); rerr != nil {
		http.Error(w, rerr.Error(), http.StatusInternalServerError)
		return
	}
	askToken := hex.EncodeToString(tb)
	if err := s.assetHandler.Store.CreateEmployeeInvite(inv); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	mintedAsks.Lock()
	mintedAsks.m[askToken] = ask
	mintedAsks.Unlock()
	writeJSON(w, map[string]interface{}{
		"invite_digest": enrolsecret.Digest(inv.Token), "token": askToken, "url": fmt.Sprintf("%s/i/%s", publicURL, askToken),
	})
}

// handleRedeemBindingInvite takes a person's statement. It spends the invite first, and gives it back
// if the statement is refused, so a refused one costs the person nothing and a taken one cannot be
// taken twice.
func (s *CoreServer) handleRedeemBindingInvite(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	var body bindingRedeem
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&body); err != nil {
		http.Error(w, "the statement could not be read", http.StatusBadRequest)
		return
	}
	inv, err := s.assetHandler.Store.ReserveBindingInvite(token)
	switch {
	case err == nil:
	case errors.Is(err, asset.ErrInviteNotFound):
		http.Error(w, "invalid invite", http.StatusBadRequest)
		return
	case errors.Is(err, asset.ErrInviteExhausted):
		http.Error(w, "invite already used", http.StatusBadRequest)
		return
	case errors.Is(err, asset.ErrInviteExpired):
		http.Error(w, "invite expired", http.StatusBadRequest)
		return
	default:
		http.Error(w, "the invite could not be redeemed", http.StatusInternalServerError)
		return
	}
	refuse := func(status int, why string) {
		_ = s.assetHandler.Store.ReleaseEmployeeInvite(token)
		http.Error(w, why, status)
	}
	id, _ := s.DataStore.GetIdentity()
	if id == nil || id.AID == "" {
		refuse(http.StatusConflict, "this organisation has no identity")
		return
	}
	st := body.Link.Statement
	if st.Role != inv.BindRole {
		refuse(http.StatusForbidden, "this invite is for another role")
		return
	}
	logs := map[string]string{st.Record: body.RecordKeyLog, st.New: body.NewKeyLog}
	err = body.Link.Verify(binding.Expect{
		Org: id.AID, Site: inv.SiteAID, Invite: enrolsecret.Digest(token),
		KeyIsCurrent: func(identifier, key string) error {
			raw, _, kerr := iacrypto.DecodeEd25519Key(key, false)
			if kerr != nil {
				return kerr
			}
			have, kerr := login.KeyFromKeyLog(identifier, logs[identifier])
			if kerr != nil {
				return kerr
			}
			if !bytes.Equal(have, raw) {
				return errors.New("it is not the key in that identifier's key log")
			}
			return nil
		},
	})
	if err != nil {
		refuse(http.StatusForbidden, err.Error())
		return
	}
	// Any identifier the record already holds may sign for it, and no other.
	held := false
	for _, known := range inv.RecordIdentifiers {
		if slices.Contains(s.assetHandler.Store.RecordOf(known), st.Record) {
			held = true
		}
	}
	if !held {
		refuse(http.StatusForbidden, "the identifier that signed for the record is not one the record holds")
		return
	}
	if inv.BindRole == binding.RoleOwner {
		// Checked again now: who the owner is may have been settled since the invite was made.
		oa, oerr := s.ownerAuthority()
		if oerr != nil || oa == nil || oa.AID != st.Record || oa.AID == id.AID {
			refuse(http.StatusForbidden, "that is not this organisation's owner")
			return
		}
		// The owner's identifier can rotate, and a key log the redeemer sends may stop
		// before a rotation. So the owner's key must be the one this organisation holds
		// as the owner's current key, not merely a key the log once had.
		ownerKey, herr := ownerKeyBytes(oa.PublicKey)
		sent, _, serr := iacrypto.DecodeEd25519Key(body.Link.RecordKey, false)
		if herr != nil || serr != nil || !bytes.Equal(ownerKey, sent) {
			refuse(http.StatusForbidden, "that is not the owner's current key")
			return
		}
	}
	err = s.assetHandler.Store.AddBinding(asset.Binding{
		Record: st.Record, New: st.New, Role: st.Role, Site: st.Site, InviteDigest: st.Invite,
		Statement: string(st.SignedBytes()), RecordSig: body.Link.RecordSig, NewSig: body.Link.NewSig,
	})
	if err != nil && !errors.Is(err, asset.ErrBindingKnown) {
		refuse(http.StatusInternalServerError, "the joining could not be kept")
		return
	}
	writeJSON(w, map[string]interface{}{"status": "bound", "role": st.Role, "record": st.Record, "identifier": st.New})
}

// ownerKeyBytes is the raw owner key, written in any spelling an owner key is sealed in.
func ownerKeyBytes(key string) ([]byte, error) {
	raw, _, err := iacrypto.DecodeEd25519Key(key, true)
	return raw, err
}

// handleListBindings lists the joinings this organisation holds. Owner only.
func (s *CoreServer) handleListBindings(w http.ResponseWriter, r *http.Request) {
	list := s.assetHandler.Store.Bindings()
	if list == nil {
		list = []asset.Binding{}
	}
	writeJSON(w, map[string]interface{}{"links": list})
}

// Bindings is the joinings the organisation holds, for an extension that keeps
// something under one record for a person who reaches it by more than one identifier.
func (s *CoreServer) Bindings() []asset.Binding {
	if s.assetHandler == nil {
		return nil
	}
	return s.assetHandler.Store.Bindings()
}

// RecordOf is every identifier joined to the record that holds id.
func (s *CoreServer) RecordOf(id string) []string {
	if s.assetHandler == nil {
		return []string{id}
	}
	return s.assetHandler.Store.RecordOf(id)
}
