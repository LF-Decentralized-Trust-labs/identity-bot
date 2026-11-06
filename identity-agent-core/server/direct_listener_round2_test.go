package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"identity-agent-core/endpoint"
	"identity-agent-core/store"
)

func askDirectHTML(h http.Handler, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// A deployment that still sets the retired variable does not start: it asked for
// reach this build no longer gives, and must be told rather than lose it.
func TestARetiredDirectIngressSettingStopsTheAgentStarting(t *testing.T) {
	t.Setenv("AGENT_DIRECT_INGRESS_ADDR", "0.0.0.0:5050")
	t.Setenv("AGENT_DIRECT_LISTEN_ADDR", "")
	err := agentWithNoIdentity(t).bindDirectListener()
	if err == nil {
		t.Fatal("started with the retired setting present")
	}
	for _, want := range []string{"AGENT_DIRECT_INGRESS_ADDR", "AGENT_DIRECT_LISTEN_ADDR"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %s: %v", want, err)
		}
	}
}

// The browser page puts the sender's ?action= into HTML and into a link: neither
// may carry it as markup, on either listener.
func TestTheOobiPageDoesNotEchoActionAsMarkup(t *testing.T) {
	s := directAgent(t)
	if err := s.DataStore.SaveIdentity(store.IdentityState{AID: allowedAID}); err != nil {
		t.Fatal(err)
	}
	payload := `"><script>alert(1)</script>`
	q := "?action=" + `%22%3E%3Cscript%3Ealert(1)%3C/script%3E`
	for name, h := range map[string]http.Handler{"direct": s.directRouter(), "root": s.buildRouter()} {
		path := "/" + allowedAID + "/oobi" + q
		if name == "root" {
			path = "/public/oobi/" + allowedAID + q
		}
		rec := askDirectHTML(h, path)
		body := rec.Body.String()
		if !strings.Contains(rec.Header().Get("Content-Type"), "html") {
			t.Fatalf("%s: no page (%d %q)", name, rec.Code, body)
		}
		if strings.Contains(body, "<script>") || strings.Contains(body, payload) {
			t.Errorf("%s: the action reached the page as markup: %s", name, body)
		}
	}
}

// On the direct listener the OOBI points at a route that listener serves.
func TestTheOobiPageLinksToARouteTheDirectListenerServes(t *testing.T) {
	s := directAgent(t)
	if err := s.DataStore.SaveIdentity(store.IdentityState{AID: allowedAID}); err != nil {
		t.Fatal(err)
	}
	body := askDirectHTML(s.directRouter(), "/"+allowedAID+"/oobi?action=add_contact").Body.String()
	if strings.Contains(body, "/public/oobi/") {
		t.Errorf("the direct page links to a route that listener does not serve: %s", body)
	}
	if !strings.Contains(body, "/"+allowedAID+"/oobi?action=add_contact") {
		t.Errorf("the direct page does not link to its own OOBI route: %s", body)
	}
	// and the root's page is unchanged
	if root := askDirectHTML(s.buildRouter(), "/public/oobi/"+allowedAID).Body.String(); !strings.Contains(root, "/public/oobi/"+allowedAID) {
		t.Errorf("the root page lost its link: %s", root)
	}
}

// did.json from the direct listener names the port it is served on.
func TestDidJSONOnTheDirectListenerNamesItsPort(t *testing.T) {
	s := directAgent(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	if err := s.DataStore.SaveContact(store.ContactRecord{
		AID: allowedAID, Alias: "x", PublicKey: base64.StdEncoding.EncodeToString(pub),
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/"+allowedAID+"/did.json", nil)
	req.Host = "192.168.0.10:5060"
	rec := httptest.NewRecorder()
	s.directRouter().ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "http://192.168.0.10:5060/"+allowedAID+"/oobi") ||
		!strings.Contains(body, "did:webs:192.168.0.10%3A5060:"+allowedAID) {
		t.Errorf("did.json does not name the direct port: %d %s", rec.Code, body)
	}
}

// A wildcard bind takes both address families, not IPv4 alone.
func TestAWildcardDirectBindIsNotIPv4Only(t *testing.T) {
	probe, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Skip(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	t.Setenv("AGENT_DIRECT_INGRESS_ADDR", "")
	t.Setenv("AGENT_DIRECT_LISTEN_ADDR", "0.0.0.0:"+strconv.Itoa(port))
	s := directAgent(t)
	if err := s.bindDirectListener(); err != nil {
		t.Fatal(err)
	}
	defer s.directSrv.Close()
	if p6, err := net.Listen("tcp6", "[::1]:0"); err != nil {
		t.Skipf("no IPv6 on this host: %v", err)
	} else {
		p6.Close()
	}
	for _, addr := range []string{"127.0.0.1:" + strconv.Itoa(port), "[::1]:" + strconv.Itoa(port)} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Errorf("the wildcard bind is not reachable at %s: %v", addr, err)
			continue
		}
		c.Close()
	}
}

// The direct listener's address is not one a controller signs for.
func TestTheDirectListenersAddressIsNotAnOriginOfTheAgent(t *testing.T) {
	t.Setenv("AGENT_DIRECT_LISTEN_ADDR", "0.0.0.0:5060")
	t.Setenv("PUBLIC_URL", "")
	for _, u := range endpoint.New(nil, 5050).OwnURLs() {
		if strings.Contains(u, "5060") {
			t.Errorf("the direct listener's address is an origin of the agent: %s", u)
		}
	}
}
