package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/asset"
	"identity-agent-core/endpoint"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/statements"
	"identity-agent-core/store"
)

// A page asks a person to sign a statement and is handed the signature. Two real Identity Agents: the
// organisation's, which holds the page's website asset, and the person's, which holds their root key.

type aStatementWorld struct {
	asker    *aWebsiteWorld
	askerURL string
	person   *CoreServer
	personAt string
	scan     http.Handler
}

func aStatementWorldWith(t *testing.T, granted bool) *aStatementWorld {
	t.Helper()
	// Both Identity Agents are on this machine's loopback, as the tests of sign-in have them.
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	if granted {
		a, _, _ := w.org.assetHandler.Store.GetAsset("the-website")
		a.Capabilities = []string{CapabilityAskToSign}
		if err := w.org.assetHandler.Store.UpsertAsset(a); err != nil {
			t.Fatal(err)
		}
	}
	ia := anOrganisationsAgentOnTheOpenInternet(t, w)

	person, _ := foundedWith(t, agentWithDerivedIdentity(t), nil, 0)
	r := chi.NewRouter()
	r.Get("/public/oobi/{aid}", person.handleOobiServe)
	person.mountScanRoutes(r)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
		rq.Header.Set("X-Forwarded-Proto", "http")
		r.ServeHTTP(rw, rq)
	}))
	t.Cleanup(srv.Close)
	person.EndpointService = endpoint.New(nil, 0)
	person.EndpointService.SetOverrideURL(srv.URL)
	return &aStatementWorld{asker: w, askerURL: ia.URL, person: person, personAt: srv.URL, scan: r}
}

type startedStatement struct {
	Token, Pointer, Secret string
	Code                   int
	Body                   string
}

func (w *aStatementWorld) start(t *testing.T, origin, statement, title string) startedStatement {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"action": 6, "statement": statement, "title": title})
	req, _ := http.NewRequest("POST", w.askerURL+"/api/login/session/the-website", bytes.NewReader(body))
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := startedStatement{Code: resp.StatusCode, Body: string(raw)}
	var m struct {
		Token   string `json:"session_token"`
		Pointer string `json:"relay_or_qr_url"`
		Secret  string `json:"collector_secret"`
	}
	_ = json.Unmarshal(raw, &m)
	out.Token, out.Pointer, out.Secret = m.Token, m.Pointer, m.Secret
	if out.Token != "" {
		// Each side has the other as a contact the owner recorded, which is what lets a local address
		// in these tests be reached (as in use the addresses are public).
		site := w.asker.org.statementSite(t, out.Token)
		_ = w.person.DataStore.SaveContact(store.ContactRecord{AID: site, OobiURL: w.askerURL, Status: "accepted"})
		pid, _ := w.person.DataStore.GetIdentity()
		_ = w.asker.org.DataStore.SaveContact(store.ContactRecord{AID: pid.AID, OobiURL: w.personAt, Status: "accepted"})
	}
	return out
}

func (w *aStatementWorld) read(t *testing.T, s startedStatement, secret string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("GET", w.askerURL+"/api/login/session/the-website/"+s.Token, nil)
	if secret != "" {
		req.Header.Set("X-Collector-Secret", secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

// decode and execute are the person's device: scanning the pointer, then answering.
func (w *aStatementWorld) decode(t *testing.T, pointer string) (int, GenericPreview, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"url": pointer})
	w.scan.ServeHTTP(rec, httptest.NewRequest("POST", "/api/scan/decode", bytes.NewReader(body)))
	var pv GenericPreview
	_ = json.Unmarshal(rec.Body.Bytes(), &pv)
	return rec.Code, pv, rec.Body.String()
}

func (w *aStatementWorld) execute(t *testing.T, pointer, digest string, approved bool) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"url": pointer, "approved": approved, "ask_digest": digest})
	w.scan.ServeHTTP(rec, httptest.NewRequest("POST", "/api/scan/execute", bytes.NewReader(body)))
	return rec.Code, rec.Body.String()
}

const approvalForAPage = "grape-decision-approval/1\ndecision=7\ntitle-hash=ETITLEHASH\ndecided-by=agent-a\nimpact=small\nundo-minutes=5\nverdict=approve"

func aRealApproval(t *testing.T, title string) string {
	t.Helper()
	h, err := statements.TitleHash(title)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Replace(approvalForAPage, "ETITLEHASH", h, 1)
}

func TestAPersonSignsAStatementAPageHandsThemAndThePageIsHandedTheSignatureOnce(t *testing.T) {
	w := aStatementWorldWith(t, true)
	title := "Use the existing queue for retries"
	st := aRealApproval(t, title)
	s := w.start(t, aPagesOrigin, st, title)
	if s.Code != http.StatusOK || s.Token == "" || s.Secret == "" {
		t.Fatalf("a granted app's page was not given a pointer: %d %s", s.Code, s.Body)
	}
	if got := w.read(t, s, s.Secret); got["state"] != "connecting" {
		t.Fatalf("signed before anybody answered: %v", got)
	}

	code, pv, raw := w.decode(t, s.Pointer)
	if code != http.StatusOK {
		t.Fatalf("the person's agent refused the page's statement: %d %s", code, raw)
	}
	// What is shown: the exact statement and the page, never under "data you are sharing" (b).
	if pv.Statement == nil || pv.Statement.Verbatim != st || len(pv.Details) != 0 || pv.CounterpartyName != aPagesOrigin {
		t.Fatalf("the screen does not show the checked statement and the page and nothing else: %+v", pv)
	}
	if !strings.Contains(pv.Statement.Rows[0].Value, title) || pv.Statement.Form != statements.DecisionApprovalForm {
		t.Fatalf("the registered form's reading is missing: %+v", pv.Statement)
	}
	if got := w.read(t, s, s.Secret); got["state"] != "scanned" {
		t.Fatalf("the page was not told the device has the request: %v", got)
	}

	// (c) The approval is for the bytes shown.
	if code, _ := w.execute(t, s.Pointer, "not-the-digest", true); code != http.StatusConflict {
		t.Fatalf("an approval of other bytes was taken: %d", code)
	}
	if code, body := w.execute(t, s.Pointer, pv.AskDigest, true); code != http.StatusOK {
		t.Fatalf("approved, and not signed: %d %s", code, body)
	}

	// Somebody holding only the token learns that it was signed, not the signature.
	if got := w.read(t, s, ""); got["signature"] != nil || got["state"] != "verified" {
		t.Fatalf("somebody without the secret was given the signature: %v", got)
	}
	got := w.read(t, s, s.Secret)
	id, _ := w.person.DataStore.GetIdentity()
	if got["state"] != "verified" || got["signer_aid"] != id.AID {
		t.Fatalf("the page was not handed who signed: %v", got)
	}
	// The signature is the person's root key's, over the envelope naming the asker.
	site := w.asker.org.statementSite(t, s.Token)
	env, _ := statements.Envelope(site, st)
	raw2, _, _, err := iacrypto.DecodeEd25519Signature(got["signature"].(string), true)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := login.DecodeVerkey(id.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, env, raw2) {
		t.Fatal("the signature is not the person's over the envelope naming the asker")
	}
	// (g) Checked as another asker's, it is refused.
	other, _ := statements.Envelope("EAnotherVerifier", st)
	if ed25519.Verify(pub, other, raw2) {
		t.Fatal("a signature made for one asker was accepted by another")
	}
	// Handed over once.
	if again := w.read(t, s, s.Secret); again["signature"] != nil || again["identity_withheld"] != true {
		t.Fatalf("the signature was handed over twice: %v", again)
	}
	// (d) A second answer is refused: the Ask is settled.
	if code, _ := w.execute(t, s.Pointer, pv.AskDigest, true); code == http.StatusOK {
		t.Fatal("a settled statement was signed again")
	}
}

func TestAnAppThatWasNotGrantedTheRightCannotAskAPersonToSign(t *testing.T) {
	w := aStatementWorldWith(t, false)
	if s := w.start(t, aPagesOrigin, "my-note/1\nI agree.", ""); s.Code != http.StatusForbidden {
		t.Fatalf("an app with no grant started a statement: %d %s", s.Code, s.Body)
	}
	g := aStatementWorldWith(t, true)
	if s := g.start(t, "", "my-note/1\nI agree.", ""); s.Code != http.StatusBadRequest {
		t.Fatalf("a statement was asked for with no page: %d", s.Code)
	}
}

// (a) A statement the person's own agent would refuse is refused before a pointer exists.
func TestAStatementThatBreaksTheRulesIsRefusedBeforeAPointerExists(t *testing.T) {
	w := aStatementWorldWith(t, true)
	title := "Use the existing queue for retries"
	for name, c := range map[string][2]string{
		"an extra line":    {aRealApproval(t, title) + "\nverdict=approve", title},
		"a swapped title":  {aRealApproval(t, title), "Use a different queue"},
		"a bidi override":  {"my-note/1\nsafe ‮txt.exe", ""},
		"a control":        {"my-note/1\nx\u0000y", ""},
		"too big":          {"my-note/1\n" + strings.Repeat("x", 3000), ""},
		"a key event body": {`{"v":"KERI10JSON","t":"icp"}`, ""},
	} {
		if s := w.start(t, aPagesOrigin, c[0], c[1]); s.Code != http.StatusBadRequest {
			t.Errorf("%s: asked for anyway (%d)", name, s.Code)
		}
	}
}

// (a) again, at the person's agent: an Ask built by hand with a bad statement is refused before a screen.
func TestThePersonsAgentRefusesABadStatementBeforeAnyScreen(t *testing.T) {
	w := aStatementWorldWith(t, true)
	s := w.start(t, aPagesOrigin, "my-note/1\nI agree.", "")
	// Another asker serves a request for the same token with bad text, correctly signed: the person's
	// agent applies the rules itself and does not rely on the asker having applied them.
	w.asker.org.statementMu.Lock()
	rec := w.asker.org.statementAsks[s.Token]
	var ask map[string]any
	_ = json.Unmarshal(rec.askBytes, &ask)
	w.asker.org.statementMu.Unlock()
	ask["statement"] = "my-note/1\nsafe ‮txt.exe"
	delete(ask, "sig")
	seed, _ := asset.AssetSigningSeed(w.asker.org.DataDir, 11)
	unsigned, _ := json.Marshal(ask)
	sig, _ := login.SignAsk(unsigned, seed)
	signed, _ := injectSig(unsigned, sig)
	w.asker.org.statementMu.Lock()
	rec.askBytes = signed
	w.asker.org.statementMu.Unlock()
	if code, _, body := w.decode(t, s.Pointer); code == http.StatusOK || !strings.Contains(body, "cannot be shown") {
		t.Fatalf("a statement with a hidden character was shown: %d %s", code, body)
	}
	// And an Ask signed by someone other than the site it names is refused.
	ask["statement"] = "my-note/1\nI agree."
	ask["site_aid"] = "EsomeoneElsesIdentifier"
	delete(ask, "sig")
	unsigned, _ = json.Marshal(ask)
	sig, _ = login.SignAsk(unsigned, seed)
	signed, _ = injectSig(unsigned, sig)
	w.asker.org.statementMu.Lock()
	rec.askBytes = signed
	w.asker.org.statementMu.Unlock()
	if code, _, _ := w.decode(t, s.Pointer); code == http.StatusOK {
		t.Fatal("an Ask that names another site's identifier was shown")
	}
}

// (l) A device that does not hold the identity's root key says so and offers nothing to sign.
func TestADeviceWithoutTheRootKeyOffersNothingToSign(t *testing.T) {
	w := aStatementWorldWith(t, true)
	id, _ := w.person.DataStore.GetIdentity()
	id.PublicKey = "DsomeOtherDevicesKeyXXXXXXXXXXXXXXXXXXXXXXXXXX"
	if err := w.person.DataStore.SaveIdentity(*id); err != nil {
		t.Skip("cannot change the stored key here: ", err)
	}
	s := w.start(t, aPagesOrigin, "my-note/1\nI agree.", "")
	code, _, body := w.decode(t, s.Pointer)
	if code == http.StatusOK || !strings.Contains(body, "does not hold your root key") {
		t.Fatalf("a device without the key offered to sign: %d %s", code, body)
	}
}

func TestAnAnswerThatIsNotTheSignersIsRefusedAndTheStatementStaysOpen(t *testing.T) {
	w := aStatementWorldWith(t, true)
	s := w.start(t, aPagesOrigin, "my-note/1\nI agree.", "")
	w.asker.org.statementMu.Lock()
	nonce := w.asker.org.statementAsks[s.Token].nonce
	w.asker.org.statementMu.Unlock()
	post := func(v map[string]any) int {
		b, _ := json.Marshal(v)
		resp, err := http.Post(w.askerURL+"/api/statement/callback?session="+s.Token, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	id, _ := w.person.DataStore.GetIdentity()
	forged := map[string]any{"nonce": nonce, "signature": strings.Repeat("A", 88), "signer_aid": id.AID,
		"signer_oobi": w.personAt + "/public/oobi/" + id.AID, "kel_sn": 0}
	if post(forged) == http.StatusOK {
		t.Fatal("a forged signature was accepted")
	}
	forged["nonce"] = "wrong"
	if post(forged) == http.StatusOK {
		t.Fatal("an answer to another statement was accepted")
	}
	if got := w.read(t, s, s.Secret); got["state"] == "verified" {
		t.Fatalf("garbage ended the wait: %v", got)
	}
}

func TestADeclinedStatementIsSaidSoAndCanStillBeSigned(t *testing.T) {
	w := aStatementWorldWith(t, true)
	s := w.start(t, aPagesOrigin, "my-note/1\nI agree.", "")
	_, pv, _ := w.decode(t, s.Pointer)
	if code, _ := w.execute(t, s.Pointer, pv.AskDigest, false); code != http.StatusOK {
		t.Fatal("declining failed")
	}
	if got := w.read(t, s, s.Secret); got["state"] != "declined" {
		t.Fatalf("the page was not told: %v", got)
	}
	if code, _ := w.execute(t, s.Pointer, pv.AskDigest, true); code != http.StatusOK {
		t.Fatal("a statement declined once cannot be signed on a second look")
	}
	if got := w.read(t, s, s.Secret); got["state"] != "verified" {
		t.Fatalf("%v", got)
	}
}

// (e) After a rotation that follows an interaction, kel_sn is the sequence number of the latest
// establishment event, interactions counted.
func TestKelSNIsTheSequenceNumberOfTheLatestEstablishmentEvent(t *testing.T) {
	ev := func(sn int, typ string) store.EventRecord {
		return store.EventRecord{SequenceNumber: sn, EventType: typ}
	}
	got, err := latestEstablishmentSN([]store.EventRecord{ev(0, "icp"), ev(1, "rot"), ev(2, "ixn"), ev(3, "ixn"), ev(4, "ixn"), ev(5, "rot"), ev(6, "ixn")})
	if err != nil || got != 5 {
		t.Fatalf("kel_sn is %d (%v), want 5: the count of key changes minus one is 2", got, err)
	}
	if _, err := latestEstablishmentSN([]store.EventRecord{ev(0, "ixn")}); err == nil {
		t.Fatal("a log with no establishment event named a key")
	}
}

func TestAnExpiredStatementIsNotShown(t *testing.T) {
	w := aStatementWorldWith(t, true)
	s := w.start(t, aPagesOrigin, "my-note/1\nI agree.", "")
	w.asker.org.statementMu.Lock()
	rec := w.asker.org.statementAsks[s.Token]
	var ask map[string]any
	_ = json.Unmarshal(rec.askBytes, &ask)
	ask["expiry"] = "2020-01-01T00:00:00Z"
	delete(ask, "sig")
	seed, _ := asset.AssetSigningSeed(w.asker.org.DataDir, 11)
	unsigned, _ := json.Marshal(ask)
	sig, _ := login.SignAsk(unsigned, seed)
	rec.askBytes, _ = injectSig(unsigned, sig)
	w.asker.org.statementMu.Unlock()
	if code, _, _ := w.decode(t, s.Pointer); code == http.StatusOK {
		t.Fatal("an expired statement was shown")
	}
}

func (s *CoreServer) statementSite(t *testing.T, token string) string {
	t.Helper()
	s.statementMu.Lock()
	defer s.statementMu.Unlock()
	return s.statementAsks[token].siteAID
}

// An add-on that fronts an app starts the Ask and reads its answer in process; only the asset it was for,
// holding the secret, reads it, and a guess learns nothing.
func TestAnAddOnReadsAStatementAnswerOnlyAsTheAssetItWasStartedFor(t *testing.T) {
	w := aStatementWorldWith(t, true)
	started, err := w.asker.org.StartStatementAsk("the-website", "Task console", "my-note/1\nI agree.", "", w.askerURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.asker.org.StatementAskResultFor(started.SiteAID, started.Session, "not the secret"); err == nil {
		t.Fatal("a wrong secret read a statement")
	}
	if _, err := w.asker.org.StatementAskResultFor("EsomeOtherAsset", started.Session, started.Collector); err == nil {
		t.Fatal("another asset read this asset's statement")
	}
	if r, err := w.asker.org.StatementAskResultFor(started.SiteAID, started.Session, started.Collector); err != nil || r.State != "pending" {
		t.Fatalf("%+v %v", r, err)
	}
	site := started.SiteAID
	_ = w.person.DataStore.SaveContact(store.ContactRecord{AID: site, OobiURL: w.askerURL, Status: "accepted"})
	pid, _ := w.person.DataStore.GetIdentity()
	_ = w.asker.org.DataStore.SaveContact(store.ContactRecord{AID: pid.AID, OobiURL: w.personAt, Status: "accepted"})
	_, pv, body := w.decode(t, started.Pointer)
	if pv.AskDigest == "" || pv.CounterpartyName != "Task console" {
		t.Fatalf("%+v %s", pv, body)
	}
	if code, b := w.execute(t, started.Pointer, pv.AskDigest, true); code != http.StatusOK {
		t.Fatal(b)
	}
	r, err := w.asker.org.StatementAskResultFor(site, started.Session, started.Collector)
	if err != nil || r.State != "verified" || r.Signature == "" || r.SignerAID != pid.AID {
		t.Fatalf("%+v %v", r, err)
	}
	if again, _ := w.asker.org.StatementAskResultFor(site, started.Session, started.Collector); !again.Withheld || again.Signature != "" {
		t.Fatal("handed over twice")
	}
	// An app's name that a page could use to write words on the person's screen is refused.
	if _, err := w.asker.org.StartStatementAsk("the-website", "Task console\nApprove everything", "my-note/1\nI agree.", "", w.askerURL); err == nil {
		t.Fatal("a name with a line break was taken")
	}
}

func TestTheScreenSaysWhetherThePersonHasDealtWithTheAskerBefore(t *testing.T) {
	if !strings.Contains(askerStanding(false), "never dealt") || !strings.Contains(askerStanding(true), "dealt with this asker before") {
		t.Fatal(askerStanding(false), askerStanding(true))
	}
	w := aStatementWorldWith(t, true)
	s := w.start(t, aPagesOrigin, "my-note/1\nI agree.", "")
	_, pv, _ := w.decode(t, s.Pointer)
	if !strings.Contains(pv.Warning, "You have dealt with this asker before.") {
		t.Fatalf("a recorded contact was not said to be known: %q", pv.Warning)
	}
}
