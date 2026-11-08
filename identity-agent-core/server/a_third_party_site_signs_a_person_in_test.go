package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/asset"
	"identity-agent-core/login"
)

// A third party's website signs a person in against an organisation's Identity
// Agent, with the login SDK on the website's server and nothing else.
//
// The website is packages/login-web/src/a-third-party-site.mjs, a Node server
// written as a site would write it (startLoginSession, confirmLoginSession,
// verifyLoginAssertion). The organisation, its website asset, the site's key
// log and the delegation approving it are real, as in
// TestAMemberSignsInToTheirOrganisationsWebsite; so is the person's Identity
// Agent, which holds only a root seed. Nothing in the chain is replaced except
// the website's own page.
func TestAThirdPartysSiteSignsAPersonInThroughTheSDK(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{
		Mode: asset.EnrollmentInvite, MembershipSource: "roster_the_website",
	})

	// The organisation's Identity Agent as the open internet sees it: the
	// routes a site and a person's agent use, and a tap on the callback so the
	// test holds the assertion the person sent.
	var mu sync.Mutex
	var posted [][]byte
	r := chi.NewRouter()
	r.Get("/public/oobi/{aid}", w.org.handleOobiServe)
	r.Get("/i/{token}", w.org.handleChallengeBundleServe)
	w.org.mountLoginWidgetRoutes(r)
	r.Post("/public/login/key", w.org.handleKeyFromKeyLog)
	r.Post("/api/login/callback", func(rw http.ResponseWriter, rq *http.Request) {
		b, _ := io.ReadAll(rq.Body)
		mu.Lock()
		posted = append(posted, b)
		mu.Unlock()
		rq.Body = io.NopCloser(bytes.NewReader(b))
		w.org.handleLoginCallback(rw, rq)
	})
	// The agent names itself https unless told otherwise, as it is behind TLS in
	// use; this one is reached over plain HTTP on the loopback.
	ia := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
		rq.Header.Set("X-Forwarded-Proto", "http")
		r.ServeHTTP(rw, rq)
	}))
	t.Cleanup(ia.Close)

	site := startThirdPartySite(t, ia.URL, "the-website")

	start := func() (token string) {
		var out struct {
			Token string `json:"session_token"`
			Url   string `json:"pointer_url"`
		}
		siteCall(t, "POST", site+"/login/start", "", 200, &out)
		if out.Token == "" || !strings.Contains(out.Url, "/i/"+out.Token) {
			t.Fatalf("the site was handed no pointer for the person: %+v", out)
		}
		return out.Token
	}
	finish := func(token string, want int) map[string]any {
		var out map[string]any
		siteCall(t, "GET", site+"/login/finish?session="+token, "", want, &out)
		return out
	}

	// A member signs in.
	token := start()
	finish(token, 202) // nobody has answered yet: the site signs nobody in
	h := aPersonsIdentityAgent(t)
	req := login.StartLoginRequest{SessionToken: token, RPSessionURL: ia.URL}
	preview, err := h.Preview(req)
	if err != nil {
		t.Fatalf("the person's Identity Agent refused the site the organisation's agent signed: %v", err)
	}
	w.roster[preview.PairwiseAID] = true
	if _, err := h.Approve(req); err != nil {
		t.Fatalf("a member's approved sign-in was not admitted: %v", err)
	}
	got := finish(token, 200)
	if got["pairwise_aid"] != preview.PairwiseAID || got["state"] != "signed-in" {
		t.Fatalf("the site signed in %v, not the person who answered (%s)", got, preview.PairwiseAID)
	}
	// The same sign-in is not accepted by the site a second time.
	finish(token, 409)

	// The assertion the person sent verifies against the key state the
	// organisation's Identity Agent publishes, once, and not again.
	mu.Lock()
	assertion := string(posted[len(posted)-1])
	mu.Unlock()
	w.org.challengeMu.Lock()
	b := w.org.challenges[token]
	w.org.challengeMu.Unlock()
	check, _ := json.Marshal(map[string]string{
		"assertion": assertion, "audience": b.Audience, "nonce": b.Nonce, "site_aid": b.SiteAID,
	})
	var first map[string]any
	siteCall(t, "POST", site+"/login/verify-assertion", string(check), 200, &first)
	if first["valid"] != true || first["pairwiseAID"] != preview.PairwiseAID {
		t.Fatalf("a genuine assertion did not verify against published key state: %v", first)
	}
	var replay map[string]any
	siteCall(t, "POST", site+"/login/verify-assertion", string(check), 401, &replay)
	if !strings.Contains(replay["reason"].(string), "already used") {
		t.Fatalf("a replayed assertion was refused, but not as spent: %v", replay)
	}

	// The organisation removes that person from its roster; the next sign-in
	// is refused by the organisation, and the site does not sign them in.
	w.roster[preview.PairwiseAID] = false
	token2 := start()
	req2 := login.StartLoginRequest{SessionToken: token2, RPSessionURL: ia.URL}
	if _, err := h.Preview(req2); err != nil {
		t.Fatalf("preview: %v", err)
	}
	if _, err := h.Approve(req2); err == nil {
		t.Fatal("somebody off the roster was admitted")
	}
	if out := finish(token2, 403); out["state"] != "declined" {
		t.Fatalf("the site did not report the refusal: %v", out)
	}
}

// startThirdPartySite runs the stand-in website and returns its address.
func startThirdPartySite(t *testing.T, iaURL, assetID string) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed, so the login SDK cannot run as a third party's server")
	}
	web := filepath.Join("..", "..", "packages", "login-web")
	for _, built := range []string{
		filepath.Join(web, "dist", "server.js"),
		filepath.Join("..", "..", "packages", "login-verify", "dist", "index.js"),
	} {
		if _, err := os.Stat(built); err != nil {
			t.Skipf("%s is not built: run `npm ci && npm run build` in packages/login-verify and packages/login-web", built)
		}
	}
	cmd := exec.Command(node, filepath.Join(web, "src", "a-third-party-site.mjs"))
	cmd.Env = append(os.Environ(), "IA_URL="+iaURL, "ASSET_ID="+assetID)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatalf("the stand-in site did not start: %v", err)
	}
	var up struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal([]byte(line), &up); err != nil || up.URL == "" {
		t.Fatalf("the stand-in site said %q", line)
	}
	return up.URL
}

func siteCall(t *testing.T, method, url, body string, want int, into any) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("%s %s: %d (wanted %d): %s", method, url, resp.StatusCode, want, raw)
	}
	if into != nil {
		_ = json.Unmarshal(raw, into)
	}
}
