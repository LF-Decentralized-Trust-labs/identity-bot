package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"identity-agent-core/asset"
	"identity-agent-core/endpoint"
	"identity-agent-core/store"
)

// An OOBI that is handed out names a relay address and never this agent's
// direct address (ADR-048 §6), and never the root identifier, which identifies
// a person in every relationship they have (ADR-036). Personal data is not in
// an OOBI at all: it reaches a counterparty only through an exchange the
// holder approved (ADR-009, Layer 2).

const rootAIDForOobiTests = "ERootIdentifierOfThePersonWhoOwnsThisAgent0000"

func ownerGet(s *CoreServer, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "127.0.0.1:4000"
	req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	w := httptest.NewRecorder()
	s.buildRouter().ServeHTTP(w, req)
	return w
}

func strangerGet(s *CoreServer, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "198.51.100.7:4000"
	w := httptest.NewRecorder()
	s.buildRouter().ServeHTTP(w, req)
	return w
}

// a core with a root identity and a profile full of personal data.
func ownerWithRootAndProfile(t *testing.T, s *CoreServer) {
	t.Helper()
	if err := s.DataStore.SaveIdentity(store.IdentityState{AID: rootAIDForOobiTests, PublicKey: "DRootPublicKeyForOobiTests"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DataStore.SaveProfile(store.ProfileData{
		FullName: "Ada Lovelace", Email: "ada@example.test", Tel: "+15550100", Photo: "PHOTOBYTES",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAnOobiIsNotMadeWhenThereIsNoRelayAddress(t *testing.T) {
	s := agentWithNoIdentity(t)
	ownerWithRootAndProfile(t, s)

	w := ownerGet(s, "/api/oobi")
	if w.Code != http.StatusConflict {
		t.Fatalf("an OOBI was made with no relay address to name: %d %s", w.Code, w.Body)
	}
	for _, leak := range []string{rootAIDForOobiTests, "127.0.0.1", "example.com", "localhost", "/public/oobi/"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Errorf("the refusal handed out %q: %s", leak, w.Body)
		}
	}
}

func TestAnOobiNamesOnlyTheRelayAddressAndAPairwiseIdentifier(t *testing.T) {
	s, _, _, cancel := relayWorld(t, relayproto.ModePrivate)
	defer cancel()
	s.KeriDriver = startedEngine(t)
	s.engineSigns()
	ownerWithRootAndProfile(t, s)
	go s.startRelay()
	defer s.Stop()
	relayURL := s.waitForRelay(t)

	w := ownerGet(s, "/api/oobi?action=add_contact")
	if w.Code != http.StatusOK {
		t.Fatalf("no OOBI was made: %d %s", w.Code, w.Body)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	oobi, _ := got["oobi_url"].(string)
	if !strings.HasPrefix(oobi, strings.TrimRight(relayURL, "/")+"/public/oobi/") {
		t.Errorf("the OOBI does not name the relay address %s: %s", relayURL, oobi)
	}
	if aid, _ := got["aid"].(string); aid == "" || aid == rootAIDForOobiTests {
		t.Errorf("the OOBI names %q, not a pairwise identifier made for this counterparty", aid)
	}
	body := w.Body.String()
	for _, leak := range []string{rootAIDForOobiTests, "DRootPublicKeyForOobiTests", ":5050", "ada@example.test", "Ada"} {
		if strings.Contains(body, leak) {
			t.Errorf("the OOBI response handed out %q: %s", leak, body)
		}
	}
	for _, field := range []string{"base_url", "endpoint_url", "public_key", "tunnel_provider"} {
		if _, ok := got[field]; ok {
			t.Errorf("the OOBI response still carries %q, which is a direct address or the root key", field)
		}
	}
}

func TestTheRootIdentifiersOobiIsServedOnlyToItsOwner(t *testing.T) {
	s := agentWithNoIdentity(t)
	ownerWithRootAndProfile(t, s)
	path := "/public/oobi/" + rootAIDForOobiTests

	if w := strangerGet(s, path); w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "DRootPublicKeyForOobiTests") {
		t.Errorf("the root identifier was handed to a counterparty: %d %s", w.Code, w.Body)
	}
	// Through a relay at an address it cannot place too. (A public address the
	// owner published serves it: TestAPublicAddressServesTheRootIdentity.)
	for _, mode := range []relayproto.Mode{relayproto.ModePrivate} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(relayproto.ContextWithPreamble(req.Context(),
			relayproto.Preamble{Allocation: "acme", Mode: mode, Host: "acme.relay.test"}))
		w := httptest.NewRecorder()
		s.buildRouter().ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("the root identifier was handed out through a %v relay address: %d %s", mode, w.Code, w.Body)
		}
	}
	if w := ownerGet(s, path); w.Code != http.StatusOK {
		t.Errorf("the owner at this computer cannot read their own OOBI: %d %s", w.Code, w.Body)
	}
}

// Serving an OOBI discloses no personal data to whoever fetches it. The route
// carries no proof of who is asking, so there is nobody it could know consented;
// a counterparty receives a profile through an exchange the holder approved.
func TestServingAnOobiDisclosesNoPersonalData(t *testing.T) {
	s := agentWithNoIdentity(t)
	ownerWithRootAndProfile(t, s)
	registerPairwiseKEL("EPairwiseForOobiPersonalDataTest", []map[string]interface{}{{"t": "icp"}})

	for name, w := range map[string]*httptest.ResponseRecorder{
		"the owner reading the root OOBI":    ownerGet(s, "/public/oobi/"+rootAIDForOobiTests),
		"a stranger reading a pairwise OOBI": strangerGet(s, "/public/oobi/EPairwiseForOobiPersonalDataTest"),
	} {
		if w.Code != http.StatusOK {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
		for _, personal := range []string{"Ada", "Lovelace", "ada@example.test", "+15550100", "PHOTOBYTES", "jcard"} {
			if strings.Contains(w.Body.String(), personal) {
				t.Errorf("%s: the response disclosed %q: %s", name, personal, w.Body)
			}
		}
	}
}

// A pairwise identifier's OOBI names no direct address: with no relay address
// it names none, and with one it names that.
func TestAPairwiseOobiNamesNoDirectAddress(t *testing.T) {
	s := agentWithNoIdentity(t)
	ownerWithRootAndProfile(t, s)
	registerPairwiseKEL("EPairwiseForOobiAddressTest", []map[string]interface{}{{"t": "icp"}})

	req := httptest.NewRequest(http.MethodGet, "/public/oobi/EPairwiseForOobiAddressTest", nil)
	req.RemoteAddr = "198.51.100.7:4000"
	req.Host = "direct.agent.example:8443"
	req.Header.Set("X-Forwarded-Host", "direct.agent.example")
	w := httptest.NewRecorder()
	s.buildRouter().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "direct.agent.example") || strings.Contains(w.Body.String(), "\"oobi\"") {
		t.Errorf("a pairwise OOBI named a direct address: %s", w.Body)
	}
}

func ownerDo(s *CoreServer, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:4000"
	req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	w := httptest.NewRecorder()
	s.buildRouter().ServeHTTP(w, req)
	return w
}

// A delegate of the root being published does not publish the root. Nearly
// every agent with a portal has an asset whose delegator is the root, so a rule
// that served the root OOBI "where a delegate of it is published" served it to
// everybody who could connect.
func TestADelegateExistingDoesNotPublishItsDelegatorsOobi(t *testing.T) {
	s := agentWithNoIdentity(t)
	ownerWithRootAndProfile(t, s)
	h, err := asset.NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.assetHandler = h
	if err := h.Store.UpsertAsset(asset.Asset{ID: "portal-1", AssetType: "app",
		PairwiseAID: "EDelegateOfTheRootForOobiTests0000000000000", DelegatorAID: rootAIDForOobiTests}); err != nil {
		t.Fatal(err)
	}
	w := strangerGet(s, "/public/oobi/"+rootAIDForOobiTests)
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "DRootPublicKeyForOobiTests") {
		t.Fatalf("the root identifier was handed to a counterparty because a delegate of it exists: %d %s", w.Code, w.Body)
	}
	// An organisation's identity is public by nature, and a person's is not.
	s.DeclaredEntityType = "organization"
	if w := strangerGet(s, "/public/oobi/"+rootAIDForOobiTests); w.Code != http.StatusOK {
		t.Errorf("an organisation's identity is not served to the member checking its site: %d %s", w.Code, w.Body)
	}
}

// The browser page names the root identifier and the address it was fetched at.
// A counterparty is shown neither; the owner is.
func TestTheOobiLandingPageNamesNeitherTheRootNorTheAddressToACounterparty(t *testing.T) {
	s := agentWithNoIdentity(t)
	ownerWithRootAndProfile(t, s)
	path := "/public/oobi/" + rootAIDForOobiTests

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "198.51.100.7:4000"
	req.Host = "direct.agent.example:8443"
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	s.buildRouter().ServeHTTP(w, req)
	// (A refusal repeats the identifier the caller typed; a page would be a leak.)
	if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "direct.agent.example") {
		t.Errorf("the landing page was handed to a counterparty: %d %s", w.Code, w.Body)
	}
	req = httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "127.0.0.1:4000"
	req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	req.Header.Set("Accept", "text/html")
	w = httptest.NewRecorder()
	s.buildRouter().ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), rootAIDForOobiTests) {
		t.Errorf("the owner is not shown their own link: %d %s", w.Code, w.Body)
	}
}

// With no relay address, a Direct-mode agent with a direct listener names the
// listener's /{aid}/oobi for a pairwise identifier it has allowlisted, and the
// listener then answers for it.
func TestADirectModeAgentWithNoRelayNamesItsDirectListener(t *testing.T) {
	t.Setenv("AGENT_DIRECT_LISTEN_ADDR", "192.0.2.4:5060")
	s := agentWithNoIdentity(t)
	if err := s.DataStore.SaveSettings(store.SettingsData{IngressMode: "direct"}); err != nil {
		t.Fatal(err)
	}
	s.KeriDriver = startedEngine(t)
	s.engineSigns()
	ownerWithRootAndProfile(t, s)

	w := ownerGet(s, "/api/oobi")
	if w.Code != http.StatusOK {
		t.Fatalf("no OOBI was made in Direct mode: %d %s", w.Code, w.Body)
	}
	var got map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	aid, _ := got["aid"].(string)
	if want := "http://192.0.2.4:5060/" + aid + "/oobi"; got["oobi_url"] != want || aid == "" || aid == rootAIDForOobiTests {
		t.Fatalf("the OOBI is %v, want %s for a pairwise identifier", got["oobi_url"], want)
	}
	if strings.Contains(w.Body.String(), rootAIDForOobiTests) {
		t.Errorf("the response names the root: %s", w.Body)
	}
	if rec := askDirect(s.directRouter(), http.MethodGet, "/"+aid+"/oobi"); rec.Code != http.StatusOK {
		t.Errorf("the direct listener does not answer for the identifier it named: %d %s", rec.Code, rec.Body)
	}
	// Outside Direct mode the same listener setting names nothing.
	if err := s.DataStore.SaveSettings(store.SettingsData{IngressMode: "relay"}); err != nil {
		t.Fatal(err)
	}
	if w := ownerGet(s, "/api/oobi"); w.Code != http.StatusConflict {
		t.Errorf("an OOBI was made outside Direct mode with no relay: %d %s", w.Code, w.Body)
	}
}

// Asking again for the same counterparty gives the same identifier, and the
// number made is bounded.
func TestAskingAgainForTheSameCounterpartyReusesTheirIdentifier(t *testing.T) {
	t.Setenv("AGENT_DIRECT_LISTEN_ADDR", "192.0.2.4:5060")
	s := agentWithNoIdentity(t)
	_ = s.DataStore.SaveSettings(store.SettingsData{IngressMode: "direct"})
	s.KeriDriver = startedEngine(t)
	s.engineSigns()
	ownerWithRootAndProfile(t, s)

	aidOf := func(path string) string {
		w := ownerGet(s, path)
		var got map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &got)
		a, _ := got["aid"].(string)
		return a
	}
	a1, a2, other := aidOf("/api/oobi?counterparty=bob"), aidOf("/api/oobi?counterparty=bob"), aidOf("/api/oobi?counterparty=carol")
	if a1 == "" || a1 != a2 {
		t.Errorf("the same counterparty was given %q then %q", a1, a2)
	}
	if other == a1 || other == "" {
		t.Errorf("a different counterparty was given %q, the same as %q", other, a1)
	}

	offers := s.oobiOffersOrLoad()
	offers.mu.Lock()
	offers.Made = maxOobiIdentifiers
	offers.mu.Unlock()
	if w := ownerGet(s, "/api/oobi?counterparty=dave"); w.Code != http.StatusTooManyRequests {
		t.Errorf("a new identifier was made past the limit: %d %s", w.Code, w.Body)
	}
	if aidOf("/api/oobi?counterparty=bob") != a1 {
		t.Errorf("a known counterparty was refused at the limit")
	}
}

// What a counterparty is handed names a relay address or is refused; it never
// falls back to the agent's direct address. Direct mode does not change that
// for invitations, which the direct listener does not serve.
func TestInvitationsAreRefusedWithNoRelayAddress(t *testing.T) {
	t.Setenv("AGENT_DIRECT_LISTEN_ADDR", "192.0.2.4:5060")
	s := agentWithNoIdentity(t)
	_ = s.DataStore.SaveSettings(store.SettingsData{IngressMode: "direct"})
	s.EndpointService = endpoint.New(nil, 5050)
	ownerWithRootAndProfile(t, s)
	h, err := asset.NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.assetHandler = h
	for _, c := range []struct{ path, body string }{
		{"/api/ask/create", `{"t":2}`},
		{"/api/signer/invites", `{}`},
		{"/api/employees/invites", `{"role":"x"}`},
	} {
		w := ownerDo(s, http.MethodPost, c.path, c.body)
		if w.Code != http.StatusConflict {
			t.Errorf("POST %s with no relay address answered %d %s", c.path, w.Code, w.Body)
		}
		for _, leak := range []string{"localhost", "192.0.2.4", ":5050"} {
			if strings.Contains(w.Body.String(), leak) {
				t.Errorf("POST %s handed out %q: %s", c.path, leak, w.Body)
			}
		}
	}
}
