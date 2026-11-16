package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/binding"
	"identity-agent-core/enrolsecret"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"

	"github.com/go-chi/chi/v5"
)

// An organisation, a place for it to be reached, and a person with an Identity Agent of their own.
type joinWorld struct {
	t      *testing.T
	org    *CoreServer
	orgURL string
	hits   *atomic.Int32 // what reached the organisation's redeem route
	people []*CoreServer
}

func newJoinWorld(t *testing.T) *joinWorld {
	t.Helper()
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	w := &joinWorld{t: t, hits: new(atomic.Int32)}
	w.org = agentWithDerivedIdentity(t)
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
	err := w.org.assetHandler.Store.CreateEmployeeInvite(asset.EmployeeInvite{
		Token: token, Purpose: asset.PurposeBinding, BindRole: role, MaxUses: 1, SiteAID: site, RecordIdentifiers: record,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	b, _ := json.Marshal(bindSitePayload{OrgName: "Org", OrgAID: "EOURS", OrgOOBI: w.orgURL, SiteAID: site, SiteOOBI: "http://127.0.0.1:1/oobi/" + site,
		SiteName: "Notes", RecordSiteAID: recordSite, Role: role, InviteToken: token})
	return b
}

func (w *joinWorld) approve(p *CoreServer, ask []byte, yes bool) (map[string]interface{}, error) {
	return bindSiteAsk{}.Execute(p, AskContext{Base: w.orgURL, Token: "x", AskBytes: ask, T: 5}, ScanDecision{Approved: yes})
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
	if _, err := (bindSiteAsk{}).Preview(p, AskContext{AskBytes: ask, T: 5}); err == nil {
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
