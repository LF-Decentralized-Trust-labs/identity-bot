package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/binding"
	"identity-agent-core/endpoint"
	"identity-agent-core/enrolsecret"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
	"identity-agent-core/login"
	"identity-agent-core/store"

	"github.com/go-chi/chi/v5"
)

// An organisation, a place for it to be reached, and a person with an Identity Agent of their own.
type joinWorld struct {
	t      *testing.T
	org    *CoreServer
	orgURL string
	hits   *atomic.Int32 // what reached the organisation's redeem route
	people []*CoreServer
	runs   map[string]bool // the sites the organisation delegated, which a test has no logs to show
}

func newJoinWorld(t *testing.T) *joinWorld {
	t.Helper()
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	w := &joinWorld{t: t, hits: new(atomic.Int32)}
	w.org = agentWithDerivedIdentity(t)
	w.runs = map[string]bool{"EOURS": true}
	st, err := asset.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w.org.assetHandler = &asset.Handler{Store: st}
	r := chi.NewRouter()
	r.Route("/api", func(r chi.Router) { w.org.mountBindingRoutes(r) })
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
		if strings.HasSuffix(rq.URL.Path, "/redeem") {
			w.hits.Add(1)
		}
		r.ServeHTTP(rw, rq)
	}))
	t.Cleanup(srv.Close)
	w.orgURL = srv.URL
	return w
}

// aPerson has an Identity Agent that already holds an identifier at each of the named sites.
func (w *joinWorld) aPerson(sites ...string) *CoreServer {
	w.t.Helper()
	p := agentWithDerivedIdentity(w.t)
	if err := p.initLoginHandler(); err != nil {
		w.t.Skipf("login engine unavailable: %v", err)
	}
	for _, s := range sites {
		if _, err := p.loginHandler.GetOrCreateRelationship(s, &login.ChallengeBundle{SiteAID: s, SiteOOBI: "http://127.0.0.1:1/oobi/" + s}); err != nil {
			w.t.Fatal(err)
		}
	}
	p.organisationKeyOf = func(_, aid string) ([]byte, error) {
		if aid != "EOURS" {
			return nil, errors.New("not the organization this stands in for")
		}
		seed, err := w.org.identitySigningSeed()
		if err != nil {
			return nil, err
		}
		return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil
	}
	p.siteIsDelegatedBy = func(site, _, org, _ string) error {
		if site == org || w.runs[site] {
			return nil
		}
		return errors.New("not delegated")
	}
	w.people = append(w.people, p)
	return p
}

func (w *joinWorld) identifierOf(p *CoreServer, site string) string {
	rel, ok := p.loginHandler.Store.Get(site)
	if !ok {
		w.t.Fatalf("no identifier at %s", site)
	}
	return rel.PairwiseAID
}

// anInvite is what the organisation holds for an invite it made, and the Ask that carries it.
func (w *joinWorld) anInvite(token, role, site, recordSite string, record ...string) (askBytes []byte) {
	w.t.Helper()
	w.runs[site], w.runs[recordSite] = true, true
	err := w.org.assetHandler.Store.CreateEmployeeInvite(asset.EmployeeInvite{
		Token: token, Purpose: asset.PurposeBinding, BindRole: role, MaxUses: 1, SiteAID: site, RecordIdentifiers: record,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return w.askFor(token, role, site, recordSite)
}

// askFor is the Ask the organisation's mint makes for an invite: the organisation signs it with its own key,
// naming where it takes the statement.
func (w *joinWorld) askFor(token, role, site, recordSite string) []byte {
	w.t.Helper()
	b, _ := json.Marshal(map[string]string{
		"v": "ASK1", "org_name": "Org", "org_aid": "EOURS", "org_oobi": w.orgURL + "/public/oobi/EOURS",
		"site_aid": site, "site_oobi": "http://127.0.0.1:1/oobi/" + site, "site_name": "Notes",
		"record_site_aid": recordSite, "record_site_oobi": "http://127.0.0.1:1/oobi/" + recordSite,
		"role": role, "invite_token": token, "redeem_url": w.orgURL + "/api/binding/invites/" + token + "/redeem",
	})
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	m["t"] = ActionBindSite
	seed, err := w.org.identitySigningSeed()
	if err != nil {
		w.t.Fatal(err)
	}
	return signedAsOrganisation(w.t, m, seed)
}

// signedAsOrganisation adds the organisation's signature to the Ask the fields describe, in the form the mint signs.
func signedAsOrganisation(t *testing.T, m map[string]interface{}, seed []byte) []byte {
	t.Helper()
	str := func(k string) string { v, _ := m[k].(string); return v }
	delete(m, "org_sig")
	sig, err := binding.SignInvite(binding.NewInvite(str("org_aid"), str("org_name"), str("site_aid"), str("site_name"), str("record_site_aid"),
		str("role"), enrolsecret.Digest(str("invite_token")), str("redeem_url")), seed)
	if err != nil {
		t.Fatal(err)
	}
	m["org_sig"] = sig
	b, _ := json.Marshal(m)
	return b
}

func (w *joinWorld) approve(p *CoreServer, ask []byte, yes bool) (map[string]interface{}, error) {
	return bindSiteAsk{}.Execute(p, AskContext{Base: w.orgURL, Token: "x", AskBytes: ask, T: ActionBindSite}, ScanDecision{Approved: yes})
}

func TestAPersonWhoApprovesHasTwoIdentifiersJoinedAndBothSidesKeepIt(t *testing.T) {
	w := newJoinWorld(t)
	p := w.aPerson("ECHAT")
	a := w.identifierOf(p, "ECHAT")
	ask := w.anInvite("tok1", binding.RolePerson, "ENOTES", "ECHAT", a)
	if _, err := w.approve(p, ask, true); err != nil {
		t.Fatal(err)
	}
	b := w.identifierOf(p, "ENOTES")
	if got := w.org.RecordOf(a); len(got) != 2 || got[0] == got[1] || !(holds(got, a) && holds(got, b)) {
		t.Fatalf("the organisation's record: %v", got)
	}
	// The person's own Identity Agent lists what it signed.
	rec := httptest.NewRecorder()
	p.handleListWhatIJoined(rec, httptest.NewRequest(http.MethodGet, "/api/login/joined", nil))
	if !strings.Contains(rec.Body.String(), b) || !strings.Contains(rec.Body.String(), a) || !strings.Contains(rec.Body.String(), `"role":"person"`) {
		t.Fatalf("what the person's Identity Agent says it joined: %s", rec.Body)
	}
	// And the invite is spent.
	if _, err := w.approve(p, ask, true); err == nil {
		t.Fatal("an invite was taken twice")
	}
}

func holds(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestNotNowSignsNothingAndSaysNothing(t *testing.T) {
	w := newJoinWorld(t)
	p := w.aPerson("ECHAT")
	ask := w.anInvite("tok1", binding.RolePerson, "ENOTES", "ECHAT", w.identifierOf(p, "ECHAT"))
	out, err := w.approve(p, ask, false)
	if err != nil || out["declined"] != true {
		t.Fatalf("%v %v", out, err)
	}
	if w.hits.Load() != 0 {
		t.Fatal("something reached the organisation after the person said not now")
	}
	if _, ok := p.loginHandler.Store.Get("ENOTES"); ok {
		t.Fatal("an identifier for the site was made for a person who said not now")
	}
}

func TestAPersonIsNotAskedToJoinFromAnIdentifierTheyDoNotHold(t *testing.T) {
	w := newJoinWorld(t)
	p := w.aPerson() // holds nothing at ECHAT
	ask := w.anInvite("tok1", binding.RolePerson, "ENOTES", "ECHAT", "EVICTIM")
	if _, err := (bindSiteAsk{}).Preview(p, AskContext{AskBytes: ask, T: ActionBindSite}); err == nil {
		t.Fatal("shown to someone who holds no identifier there")
	}
	if _, err := w.approve(p, ask, true); err == nil {
		t.Fatal("signed for an identifier the person does not hold")
	}
	if _, ok := p.loginHandler.Store.Get("ECHAT"); ok {
		t.Fatal("an identifier was made to sign for")
	}
	if w.hits.Load() != 0 {
		t.Fatal("something was sent")
	}
}

// post sends a statement to the organisation's redeem route as anyone holding the code could.
func (w *joinWorld) post(token string, body bindingRedeem) (int, string) {
	b, _ := json.Marshal(body)
	resp, err := http.Post(w.orgURL+"/api/binding/invites/"+token+"/redeem", "application/json", bytes.NewReader(b))
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String()
}

// link makes the statement a person's Identity Agent would, from the keys of two sites, with the
// invite named by its code, for a test that wants to send it by hand or to change it first.
func (w *joinWorld) link(p *CoreServer, token, role, recordSite, newSite string, change func(*binding.Statement)) bindingRedeem {
	w.t.Helper()
	rec, _ := p.loginHandler.Store.Get(recordSite)
	nw, err := p.loginHandler.GetOrCreateRelationship(newSite, &login.ChallengeBundle{SiteAID: newSite, SiteOOBI: "http://127.0.0.1:1/oobi/" + newSite})
	if err != nil {
		w.t.Fatal(err)
	}
	rs, _ := p.loginHandler.RelationshipSeed(&rec)
	ns, _ := p.loginHandler.RelationshipSeed(nw)
	st := binding.Statement{V: binding.Version, Org: "EOURS", Site: newSite, Record: rec.PairwiseAID, New: nw.PairwiseAID, Invite: enrolsecret.Digest(token), Role: role}
	if change != nil {
		change(&st)
	}
	l, err := binding.Sign(st, rs, ns)
	if err != nil {
		w.t.Fatal(err)
	}
	rl, _ := p.loginHandler.RelationshipKeyLog(&rec, rs)
	nl, _ := p.loginHandler.RelationshipKeyLog(nw, ns)
	return bindingRedeem{Link: l, RecordKeyLog: rl, NewKeyLog: nl}
}

func TestSomeoneWhoHoldsOnlyTheNewIdentifierCannotHaveItJoinedToAnotherPersonsRecord(t *testing.T) {
	w := newJoinWorld(t)
	victim := w.aPerson("ECHAT")
	a := w.identifierOf(victim, "ECHAT") // the victim's record
	attacker := w.aPerson("EOTHER")
	w.anInvite("tok1", binding.RolePerson, "ENOTES", "ECHAT", a)

	// Signed only with keys the attacker holds, claiming the victim's identifier for the record.
	forged := w.link(attacker, "tok1", binding.RolePerson, "EOTHER", "ENOTES", func(s *binding.Statement) { s.Record = a })
	if code, why := w.post("tok1", forged); code != http.StatusForbidden || !strings.Contains(why, "key") {
		t.Fatalf("a statement claiming a record whose key the signer does not hold: %d %s", code, why)
	}
	// Their own identifier, honestly signed with both keys, is not one the record holds.
	honest := w.link(attacker, "tok1", binding.RolePerson, "EOTHER", "ENOTES", nil)
	if code, why := w.post("tok1", honest); code != http.StatusForbidden || !strings.Contains(why, "not one the record holds") {
		t.Fatalf("an identifier the record does not hold: %d %s", code, why)
	}
	if got := w.org.RecordOf(a); len(got) != 1 {
		t.Fatalf("the victim's record changed: %v", got)
	}
	// Refusals spent nothing: the person the invite was for can still redeem it.
	good := w.link(victim, "tok1", binding.RolePerson, "ECHAT", "ENOTES", nil)
	if code, why := w.post("tok1", good); code != http.StatusOK {
		t.Fatalf("the refused statements spent the invite: %d %s", code, why)
	}
}

func TestAStatementForAnotherInviteOrSiteOrRoleIsRefused(t *testing.T) {
	w := newJoinWorld(t)
	p := w.aPerson("ECHAT")
	a := w.identifierOf(p, "ECHAT")
	w.anInvite("tok1", binding.RolePerson, "ENOTES", "ECHAT", a)
	w.anInvite("tok2", binding.RolePerson, "ENOTES", "ECHAT", a)
	for name, c := range map[string]struct {
		token  string
		change func(*binding.Statement)
	}{
		"made for tok2, sent to tok1": {"tok1", func(s *binding.Statement) { s.Invite = enrolsecret.Digest("tok2") }},
		"another organisation":        {"tok1", func(s *binding.Statement) { s.Org = "EELSEWHERE" }},
		"the owner's role":            {"tok1", func(s *binding.Statement) { s.Role = binding.RoleOwner }},
	} {
		b := w.link(p, "tok1", binding.RolePerson, "ECHAT", "ENOTES", c.change)
		if code, _ := w.post(c.token, b); code == http.StatusOK {
			t.Errorf("%s was accepted", name)
		}
	}
	// A different site than the invite is for.
	b := w.link(p, "tok1", binding.RolePerson, "ECHAT", "EWRONGSITE", nil)
	if code, _ := w.post("tok1", b); code == http.StatusOK {
		t.Error("a statement for another site was accepted")
	}
	if len(w.org.Bindings()) != 0 {
		t.Fatalf("something was kept: %v", w.org.Bindings())
	}
}

// An invite is for what it was made for.
func TestABindingInviteIsNotAnEmploymentInviteAndTheReverse(t *testing.T) {
	w := newJoinWorld(t)
	st := w.org.assetHandler.Store
	w.anInvite("bind", binding.RolePerson, "ENOTES", "ECHAT", "EA")
	if err := st.CreateEmployeeInvite(asset.EmployeeInvite{Token: "emp", Role: "x", MaxUses: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReserveEmployeeInvite("bind", false); err == nil {
		t.Fatal("a binding invite was taken as an employment invite")
	}
	if _, err := st.ReserveBindingInvite("emp"); err == nil {
		t.Fatal("an employment invite was taken as a binding invite")
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("token", "bind")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w.org.assetHandler.HandleGetEmployeeInviteInfo(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("the employment invite lookup described a binding invite")
	}
}

// Any identifier the record already holds may sign for it.
func TestAnIdentifierAlreadyJoinedToARecordMaySignForIt(t *testing.T) {
	w := newJoinWorld(t)
	p := w.aPerson("ECHAT")
	a := w.identifierOf(p, "ECHAT")
	if _, err := w.approve(p, w.anInvite("tok1", binding.RolePerson, "ENOTES", "ECHAT", a), true); err != nil {
		t.Fatal(err)
	}
	// A third identifier joins through the second, which the record holds since the first joining.
	ask := w.anInvite("tok2", binding.RolePerson, "EMORE", "ENOTES", a)
	if _, err := w.approve(p, ask, true); err != nil {
		t.Fatalf("an identifier the record holds could not sign for it: %v", err)
	}
	if got := w.org.RecordOf(a); len(got) != 3 {
		t.Fatalf("%v", got)
	}
}

func TestTwoRecordsOfOnePersonBecomeOneByAStatementSignedWithAKeyOfEach(t *testing.T) {
	w := newJoinWorld(t)
	p := w.aPerson("ECHAT", "ECHAT2")
	a, c := w.identifierOf(p, "ECHAT"), w.identifierOf(p, "ECHAT2")
	if _, err := w.approve(p, w.anInvite("tok1", binding.RolePerson, "ENOTES", "ECHAT", a), true); err != nil {
		t.Fatal(err)
	}
	if _, err := w.approve(p, w.anInvite("tok2", binding.RolePerson, "ENOTES2", "ECHAT2", c), true); err != nil {
		t.Fatal(err)
	}
	if got := w.org.RecordOf(a); holds(got, c) {
		t.Fatalf("two records were one before anyone said so: %v", got)
	}
	// The person says so: one statement, a key of each record. The new identifier is the other record's.
	if _, err := w.approve(p, w.anInvite("tok3", binding.RolePerson, "ENOTES2", "ECHAT", a), true); err != nil {
		t.Fatal(err)
	}
	got := w.org.RecordOf(a)
	if !holds(got, c) || !holds(got, w.identifierOf(p, "ENOTES2")) {
		t.Fatalf("the records were not joined: %v", got)
	}
}

func TestTheOwnerCannotJoinAsAnIdentifierTheOrganisationCannotCheck(t *testing.T) {
	w := newJoinWorld(t)
	rec := httptest.NewRecorder()
	body := `{"site_aid":"ENOTES","record_site_aid":"EORG","role":"owner"}`
	w.org.handleCreateBindingInvite(rec, httptest.NewRequest(http.MethodPost, "/api/binding/invites", strings.NewReader(body)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("an organisation that is its own authority invited an owner: %d %s", rec.Code, rec.Body)
	}
	for _, bad := range []string{`{"site_aid":"ENOTES","record_site_aid":"ENOTES","role":"person","record_identifiers":["EA"]}`,
		`{"site_aid":"ENOTES","record_site_aid":"EC","role":"person"}`, `{"site_aid":"ENOTES","record_site_aid":"EC","role":"admin"}`} {
		rec := httptest.NewRecorder()
		w.org.handleCreateBindingInvite(rec, httptest.NewRequest(http.MethodPost, "/api/binding/invites", strings.NewReader(bad)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, rec.Code)
		}
	}
}

func TestTheOwnersJoinNeedsTheOwnersOwnKeyAndNobodyElseCanTakeTheRole(t *testing.T) {
	w := newJoinWorld(t)
	owner := w.aPerson("EORGSITE")
	ownerAID := w.identifierOf(owner, "EORGSITE")
	rel, _ := owner.loginHandler.Store.Get("EORGSITE")
	// The organisation's owner is sealed to the owner's identifier and key.
	seed, _ := owner.loginHandler.RelationshipSeed(&rel)
	if err := w.org.SealOwnerAuthority(OwnerAuthority{AID: ownerAID, PublicKey: iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))}); err != nil {
		t.Fatal(err)
	}
	ask := w.anInvite("own", binding.RoleOwner, "ENOTES", "EORGSITE", ownerAID)

	// Someone else, honestly signing with their own two keys, is not the owner.
	other := w.aPerson("EORGSITE")
	forged := w.link(other, "own", binding.RoleOwner, "EORGSITE", "ENOTES", nil)
	if code, _ := w.post("own", forged); code == http.StatusOK {
		t.Fatal("somebody who is not the owner took the owner's role")
	}
	if _, err := w.approve(owner, ask, true); err != nil {
		t.Fatalf("the owner could not join: %v", err)
	}
	found := false
	for _, b := range w.org.Bindings() {
		found = found || (b.Role == binding.RoleOwner && b.Record == ownerAID)
	}
	if !found {
		t.Fatalf("%v", w.org.Bindings())
	}
}

// An organisation may name only its own sites. Otherwise it could name, as the place the record's
// identifier is from, any site the person holds an identifier at, and the statement would hand it that one.
func TestAPersonIsNeverAskedToJoinFromASiteTheOrganisationDoesNotRun(t *testing.T) {
	w := newJoinWorld(t)
	p := w.aPerson("EBANK")
	bank := w.identifierOf(p, "EBANK")
	ask := w.anInvite("tok1", binding.RolePerson, "ENOTES", "EBANK", bank)
	delete(w.runs, "EBANK") // the organisation does not run the bank
	if _, err := (bindSiteAsk{}).Preview(p, AskContext{AskBytes: ask, T: ActionBindSite}); err == nil || !strings.Contains(err.Error(), "not one this organization runs") {
		t.Fatalf("shown a request that names somebody else's site as the organisation's: %v", err)
	}
	if _, err := w.approve(p, ask, true); err == nil {
		t.Fatal("signed with an identifier at a site the organisation does not run")
	}
	if w.hits.Load() != 0 {
		t.Fatal("the person's identifier at another site was sent")
	}
	if _, ok := p.loginHandler.Store.Get("ENOTES"); ok {
		t.Fatal("an identifier was made")
	}
	// And the new side: a site that is not the organisation's is not one an identifier is made at.
	w.runs["EBANK"] = true
	ask = w.anInvite("tok2", binding.RolePerson, "EBANK2", "EBANK", bank)
	delete(w.runs, "EBANK2")
	if _, err := w.approve(p, ask, true); err == nil || !strings.Contains(err.Error(), "site is not one") {
		t.Fatalf("an identifier was made at a site the organisation does not run: %v", err)
	}
	// With no stand-in, the real check reads the site's own log, and a site that serves none is refused.
	p.siteIsDelegatedBy = nil
	if _, err := w.approve(p, w.anInvite("tok3", binding.RolePerson, "ENOTES3", "EBANK", bank), true); err == nil {
		t.Fatal("a site that shows no log of being delegated was taken for the organisation's")
	}
}

// A person's Identity Agent holds no organisation's store, and still serves the list of what they joined.
func TestAPersonsIdentityAgentServesWhatTheyJoinedWithNoOrganisationStore(t *testing.T) {
	w := newJoinWorld(t)
	p := w.aPerson("ECHAT")
	if p.assetHandler != nil {
		t.Fatal("the person's Identity Agent was given an organisation's store")
	}
	if _, err := w.approve(p, w.anInvite("tok1", binding.RolePerson, "ENOTES", "ECHAT", w.identifierOf(p, "ECHAT")), true); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	r.Route("/api", func(r chi.Router) { p.mountBindingRoutes(r) })
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/login/joined", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"role":"person"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

// resign replaces the organisation's signature on an Ask with another key's, or lets a change be made first.
func resign(t *testing.T, ask []byte, seed []byte, change func(map[string]interface{})) []byte {
	t.Helper()
	var m map[string]interface{}
	_ = json.Unmarshal(ask, &m)
	if change != nil {
		change(m)
	}
	return signedAsOrganisation(t, m, seed)
}

// Anybody can name a real organisation and its real sites. Only the organisation can sign for itself.
func TestAnAskNamingAnOrganisationThatDidNotSignItIsRefusedAndNothingIsSent(t *testing.T) {
	w := newJoinWorld(t)
	p := w.aPerson("ECHAT")
	a := w.identifierOf(p, "ECHAT")
	genuine := w.anInvite("tok1", binding.RolePerson, "ENOTES", "ECHAT", a)
	stranger := make([]byte, ed25519.SeedSize)
	stranger[0] = 7
	var m map[string]interface{}
	_ = json.Unmarshal(genuine, &m)
	for name, ask := range map[string][]byte{
		"signed by another key":          resign(t, genuine, stranger, nil),
		"with no organisation signature": func() []byte { delete(m, "org_sig"); b, _ := json.Marshal(m); return b }(),
		"a redeem address changed after": func() []byte {
			var n map[string]interface{}
			_ = json.Unmarshal(genuine, &n)
			n["redeem_url"] = "http://127.0.0.1:1/api/binding/invites/tok1/redeem"
			b, _ := json.Marshal(n)
			return b
		}(),
		"a redeem address for another invite": resign(t, genuine, mustSeed(t, w), func(m map[string]interface{}) { m["redeem_url"] = w.orgURL + "/api/binding/invites/other/redeem" }),
	} {
		if _, err := (bindSiteAsk{}).Preview(p, AskContext{AskBytes: ask, T: ActionBindSite}); err == nil {
			t.Errorf("%s: shown to the person", name)
		}
		if _, err := w.approve(p, ask, true); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	if w.hits.Load() != 0 {
		t.Fatal("a statement was sent for an Ask the organisation did not sign")
	}
	if _, ok := p.loginHandler.Store.Get("ENOTES"); ok {
		t.Fatal("an identifier was made for it")
	}
}

func mustSeed(t *testing.T, w *joinWorld) []byte {
	t.Helper()
	seed, err := w.org.identitySigningSeed()
	if err != nil {
		t.Fatal(err)
	}
	return seed
}

// A genuine Ask carried by somebody else's host still sends the statement only where the organisation said.
func TestAGenuineAskServedFromAnotherHostSendsTheStatementOnlyToTheOrganisation(t *testing.T) {
	w := newJoinWorld(t)
	p := w.aPerson("ECHAT")
	genuine := w.anInvite("tok1", binding.RolePerson, "ENOTES", "ECHAT", w.identifierOf(p, "ECHAT"))
	var relayed atomic.Int32
	relay := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/redeem") {
			relayed.Add(1)
			return
		}
		_, _ = rw.Write(genuine) // the relay serves the Ask it copied
	}))
	defer relay.Close()
	ctx, err := p.buildAskContext(relay.URL + "/i/tok1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (bindSiteAsk{}).Execute(p, ctx, ScanDecision{Approved: true}); err != nil {
		t.Fatal(err)
	}
	if relayed.Load() != 0 {
		t.Fatal("the statement went to the host that served the Ask")
	}
	if w.hits.Load() != 1 {
		t.Fatalf("the organisation took %d statements, want 1", w.hits.Load())
	}
}

// With nothing standing in, the organisation's key is read from its own log, and one that cannot be read signs nothing.
func TestAnOrganisationWhoseKeyLogCannotBeReadIsNotTakenForItself(t *testing.T) {
	w := newJoinWorld(t)
	p := w.aPerson("ECHAT")
	ask := w.anInvite("tok1", binding.RolePerson, "ENOTES", "ECHAT", w.identifierOf(p, "ECHAT"))
	p.organisationKeyOf = nil // the real check: w.orgURL serves no log for EOURS
	if _, err := w.approve(p, ask, true); err == nil || !strings.Contains(err.Error(), "own key could not be established") {
		t.Fatalf("an organization whose log could not be read was accepted: %v", err)
	}
	if w.hits.Load() != 0 {
		t.Fatal("something was sent")
	}
}

// The Ask the organisation's own route mints is the one a person scans: it is decoded and approved through the
// scan routes, which check its signature before anything else, not handed to the handler directly.
func TestAnInviteMintedByTheOrganisationCanBeScannedAndApproved(t *testing.T) {
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	org := adoptingOwner(t)
	st, err := asset.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	org.assetHandler = &asset.Handler{Store: st}
	var hits atomic.Int32
	r := chi.NewRouter()
	r.Route("/api", func(r chi.Router) { org.mountBindingRoutes(r) })
	r.Get("/public/oobi/{aid}", org.handleOobiServe)
	r.Get("/i/{token}", func(rw http.ResponseWriter, rq *http.Request) {
		b, ok := getMintedAsk(chi.URLParam(rq, "token"))
		if !ok {
			http.NotFound(rw, rq)
			return
		}
		_, _ = rw.Write(b)
	})
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
		if strings.HasSuffix(rq.URL.Path, "/redeem") {
			hits.Add(1)
		}
		r.ServeHTTP(rw, rq)
	}))
	defer srv.Close()
	org.EndpointService.SetOverrideURL(srv.URL)

	w := &joinWorld{t: t, org: org, orgURL: srv.URL, hits: &hits, runs: map[string]bool{}}
	p := w.aPerson("ECHAT")
	w.runs["ENOTES"], w.runs["ECHAT"] = true, true
	orgID, _ := org.DataStore.GetIdentity()
	// The owner added this organisation as a contact at its (local) address, which is what lets its
	// introductions be read from here; nothing else about the signature check is stood in for.
	if err := p.DataStore.SaveContact(store.ContactRecord{AID: orgID.AID, OobiURL: srv.URL + "/public/oobi/" + orgID.AID}); err != nil {
		t.Fatal(err)
	}
	p.organisationKeyOf = func(_, aid string) ([]byte, error) {
		if aid != orgID.AID {
			return nil, errors.New("not the organization")
		}
		seed, err := org.identitySigningSeed()
		if err != nil {
			return nil, err
		}
		return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil
	}
	body := `{"site_aid":"ENOTES","site_oobi":"http://127.0.0.1:1/oobi/ENOTES","record_site_aid":"ECHAT","record_site_oobi":"http://127.0.0.1:1/oobi/ECHAT","role":"person","record_identifiers":["` + w.identifierOf(p, "ECHAT") + `"]}`
	rec := httptest.NewRecorder()
	org.handleCreateBindingInvite(rec, httptest.NewRequest(http.MethodPost, "/api/binding/invites", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("minting: %d %s", rec.Code, rec.Body)
	}
	var minted struct{ URL string }
	_ = json.Unmarshal(rec.Body.Bytes(), &minted)

	post := func(h http.HandlerFunc, payload string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(payload)))
		return rr
	}
	dec := post(p.handleScanDecode, `{"url":"`+minted.URL+`"}`)
	if dec.Code != http.StatusOK {
		t.Fatalf("the minted invite could not be scanned: %d %s", dec.Code, dec.Body)
	}
	var pv GenericPreview
	_ = json.Unmarshal(dec.Body.Bytes(), &pv)
	if pv.Action != "bind_site" || !strings.Contains(dec.Body.String(), "Joining as") {
		t.Fatalf("%s", dec.Body)
	}
	ex := post(p.handleScanExecute, `{"url":"`+minted.URL+`","approved":true,"ask_digest":"`+pv.AskDigest+`"}`)
	if ex.Code != http.StatusOK {
		t.Fatalf("the minted invite could not be approved: %d %s", ex.Code, ex.Body)
	}
	if hits.Load() != 1 || len(org.Bindings()) != 1 {
		t.Fatalf("the organisation took %d statements and keeps %d joinings", hits.Load(), len(org.Bindings()))
	}
}

// A real organisation: founded here with the engine, its key log served at its own address, and nothing standing in for
// the check that the key it signs an invite with is the current key in that log. (What stays stood in is only that the
// organisation delegated the two sites, which has no real site to read here, and the person's contact for its local address.)
func TestAnInviteFromARealFoundedOrganisationIsAcceptedThroughItsOwnKeyLog(t *testing.T) {
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	aMachineThatMayFound(t)
	org := witnessWithSeed(t, 1)
	org.KeriDriver = keriengine.New()
	org.engineSigns()
	org.EndpointService = endpoint.New(nil, 0)
	st, err := asset.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	org.assetHandler = &asset.Handler{Store: st}
	router := org.buildRouter()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
		if strings.HasSuffix(rq.URL.Path, "/redeem") {
			hits.Add(1)
		}
		router.ServeHTTP(rw, rq)
	}))
	defer srv.Close()
	org.EndpointService.SetOverrideURL(srv.URL)

	founding, _ := json.Marshal(ourFounding(t, org))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, local("POST", "/api/inception", string(founding)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("founding the organisation: %d %s", rec.Code, rec.Body)
	}
	orgID, _ := org.DataStore.GetIdentity()

	w := &joinWorld{t: t, org: org, orgURL: srv.URL, hits: &hits, runs: map[string]bool{}}
	p := w.aPerson("ECHAT")
	p.organisationKeyOf = nil // the real path: the organisation's key from its own log
	w.runs["ENOTES"], w.runs["ECHAT"] = true, true
	w.runs[orgID.AID] = true
	if err := p.DataStore.SaveContact(store.ContactRecord{AID: orgID.AID, OobiURL: srv.URL + "/public/oobi/" + orgID.AID}); err != nil {
		t.Fatal(err)
	}
	body := `{"site_aid":"ENOTES","site_oobi":"http://127.0.0.1:1/oobi/ENOTES","record_site_aid":"ECHAT","record_site_oobi":"http://127.0.0.1:1/oobi/ECHAT","role":"person","record_identifiers":["` + w.identifierOf(p, "ECHAT") + `"]}`
	rec = httptest.NewRecorder()
	org.handleCreateBindingInvite(rec, httptest.NewRequest(http.MethodPost, "/api/binding/invites", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("minting: %d %s", rec.Code, rec.Body)
	}
	var minted struct{ URL string }
	_ = json.Unmarshal(rec.Body.Bytes(), &minted)
	post := func(h http.HandlerFunc, payload string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(payload)))
		return rr
	}
	dec := post(p.handleScanDecode, `{"url":"`+minted.URL+`"}`)
	if dec.Code != http.StatusOK {
		t.Fatalf("an invite signed with the real organisation key was refused: %d %s", dec.Code, dec.Body)
	}
	var pv GenericPreview
	_ = json.Unmarshal(dec.Body.Bytes(), &pv)
	if ex := post(p.handleScanExecute, `{"url":"`+minted.URL+`","approved":true,"ask_digest":"`+pv.AskDigest+`"}`); ex.Code != http.StatusOK {
		t.Fatalf("approving: %d %s", ex.Code, ex.Body)
	}
	if hits.Load() != 1 || len(org.Bindings()) != 1 {
		t.Fatalf("%d statements, %d joinings", hits.Load(), len(org.Bindings()))
	}
}

// The statement and both key logs are not sent in the clear.
func TestTheStatementIsNotSentToAnAddressThatIsNotHttps(t *testing.T) {
	w := newJoinWorld(t)
	p := w.aPerson("ECHAT")
	ask := w.anInvite("tok1", binding.RolePerson, "ENOTES", "ECHAT", w.identifierOf(p, "ECHAT"))
	t.Setenv("IA_ALLOW_LOCAL_SITES", "") // an owner who has not said local sites are fine
	if _, err := w.approve(p, ask, true); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("a statement was sent over http: %v", err)
	}
	if w.hits.Load() != 0 {
		t.Fatal("something was sent")
	}
}

// A mint that cannot sign leaves no invite behind, and the owner's list holds employment invites only.
func TestAMintThatCannotSignLeavesNoInviteAndTheEmployeeListIsEmploymentOnly(t *testing.T) {
	w := newJoinWorld(t)
	w.anInvite("tok1", binding.RolePerson, "ENOTES", "ECHAT", "EA") // a binding invite already kept
	if err := w.org.assetHandler.Store.CreateEmployeeInvite(asset.EmployeeInvite{Token: "emp", Role: "Admin", MaxUses: 1}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	w.org.assetHandler.HandleListEmployeeInvites(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if strings.Contains(rec.Body.String(), "binding") || !strings.Contains(rec.Body.String(), "Admin") {
		t.Fatalf("the employee invite list: %s", rec.Body)
	}
	before := len(w.org.assetHandler.Store.ListEmployeeInvites())
	body := `{"site_aid":"E bad site","record_site_aid":"EC","role":"person","record_identifiers":["EA"]}`
	rec = httptest.NewRecorder()
	w.org.EndpointService = endpoint.New(nil, 0)
	w.org.handleCreateBindingInvite(rec, httptest.NewRequest(http.MethodPost, "/api/binding/invites", strings.NewReader(body)))
	if rec.Code == http.StatusOK {
		t.Fatalf("an invite that cannot be signed was minted: %s", rec.Body)
	}
	if after := len(w.org.assetHandler.Store.ListEmployeeInvites()); after != before {
		t.Fatalf("a failed mint left %d invites behind", after-before)
	}
}
