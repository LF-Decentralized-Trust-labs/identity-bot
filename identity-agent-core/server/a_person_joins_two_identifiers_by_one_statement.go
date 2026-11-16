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
// with both keys (ADR-080). This file has both sides: the organisation's, which
// mints the invite and checks the statement, and the person's, the Ask (t=5)
// that asks them and signs.

// ---- the person's side: t=5, bind_site ----

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
	Role          string `json:"role"`
	InviteToken   string `json:"invite_token"`
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
	// Refused before it is shown: a person cannot be asked to join an identifier
	// they do not hold, and asking would only invite an approval that signs nothing.
	if _, ok := s.loginHandler.Store.Get(p.RecordSiteAID); !ok {
		return GenericPreview{}, errors.New("you have no identifier at the place this joins you from, so there is nothing to join this to")
	}
	org := firstOf(p.OrgName, p.OrgAID)
	site := firstOf(p.SiteName, p.SiteAID)
	return GenericPreview{
		T: 5, Action: "bind_site", Title: "Join " + site,
		Subtitle: org + " asks you to join " + site + " as the same person you are to them", Counterparty: p.OrgAID,
		Details: []PreviewDetail{{Label: "Organization", Value: org}, {Label: "Site", Value: site}},
		Warning: org + " will know that you here and you where you already deal with them are the same person. This cannot be undone except by leaving.",
	}, nil
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
	// The record's identifier must be one this person already holds. It is looked up
	// and never made: making one would sign for an identifier nobody had.
	recRel, ok := s.loginHandler.Store.Get(p.RecordSiteAID)
	if !ok || recRel.PairwiseAID == "" {
		return nil, errors.New("you have no identifier at the place this joins you from")
	}
	newRel, rerr := s.loginHandler.GetOrCreateRelationship(p.SiteAID, &login.ChallengeBundle{SiteAID: p.SiteAID, SiteOOBI: p.SiteOOBI})
	if rerr != nil || newRel == nil || newRel.PairwiseAID == "" {
		return nil, fmt.Errorf("derive the identifier for the site: %w", rerr)
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
	redeemURL := strings.TrimRight(ctx.Base, "/") + "/api/binding/invites/" + p.InviteToken + "/redeem"
	resp, err := siteClient(15*time.Second, redeemURL).Post(redeemURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("send the statement: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return nil, fmt.Errorf("the organization declined: %s", strings.TrimSpace(string(msg)))
	}
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
	if s.assetHandler == nil {
		return
	}
	r.Route("/binding", func(r chi.Router) {
		// Owner only: nobody else may ask a person to join a site.
		r.Post("/invites", s.handleCreateBindingInvite)
		r.Get("/links", s.handleListBindings)
		// Public: the person's own Identity Agent redeems here (t=5). The invite is
		// single use, and what it takes is a statement only the person's two keys can make.
		r.Post("/invites/{token}/redeem", s.handleRedeemBindingInvite)
	})
	r.Get("/login/joined", s.handleListWhatIJoined)
}

type bindingInviteRequest struct {
	SiteAID           string   `json:"site_aid"`
	SiteOOBI          string   `json:"site_oobi"`
	SiteName          string   `json:"site_name"`
	RecordSiteAID     string   `json:"record_site_aid"`
	RecordIdentifiers []string `json:"record_identifiers"`
	Role              string   `json:"role"`
}

// handleCreateBindingInvite mints a single-use invite and its Ask (t=5).
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
	publicURL := s.EndpointService.CurrentURL()
	if publicURL == "" {
		publicURL = s.getPublicURL(r)
	}
	orgName := ""
	if prof, _ := s.DataStore.GetProfile(); prof != nil {
		orgName = firstOf(prof.OrgName, prof.FullName)
	}
	inv := asset.EmployeeInvite{
		Token: genInviteToken(), Purpose: asset.PurposeBinding, BindRole: req.Role, MaxUses: 1,
		SiteAID: req.SiteAID, SiteOOBI: req.SiteOOBI, RecordIdentifiers: req.RecordIdentifiers,
	}
	if err := s.assetHandler.Store.CreateEmployeeInvite(inv); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _, seed, err := s.mintPairwise("binding")
	if err != nil {
		if refuseIfRootSeedRefused(w, err) {
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ask, _ := json.Marshal(map[string]interface{}{
		"v": "ASK1", "t": 5, "org_name": orgName, "org_aid": id.AID,
		"org_oobi": fmt.Sprintf("%s/public/oobi/%s", publicURL, id.AID),
		"site_aid": req.SiteAID, "site_oobi": req.SiteOOBI, "site_name": req.SiteName,
		"record_site_aid": req.RecordSiteAID, "role": req.Role, "invite_token": inv.Token,
	})
	sig, serr := login.SignAsk(ask, seed)
	if serr != nil {
		http.Error(w, serr.Error(), http.StatusInternalServerError)
		return
	}
	if signed, ierr := injectSig(ask, sig); ierr == nil {
		ask = signed
	}
	tb := make([]byte, 16)
	if _, rerr := rand.Read(tb); rerr != nil {
		http.Error(w, rerr.Error(), http.StatusInternalServerError)
		return
	}
	askToken := hex.EncodeToString(tb)
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
