package server

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/asset"
	"identity-agent-core/login"
)

// A third party's web page with only the login SDK, no back end of its own,
// signs a person in against the website owner's Identity Agent, using its
// public login routes only, and checks the assertion it was handed in the page.
//
// The page is packages/login-web/src/a-page-with-only-the-sdk.mjs, driven line
// by line. The organisation, its website asset, the site's key log and the
// person's Identity Agent are real, as in TestAThirdPartysSiteSignsAPersonInThroughTheSDK.
const aPagesOrigin = "https://portal.example"

func TestAPageWithOnlyTheSDKSignsAPersonIn(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	ia := anOrganisationsAgentOnTheOpenInternet(t, w)
	page := startAPageWithOnlyTheSDK(t, ia.URL, "the-website", aPagesOrigin)

	started := page.say(t, "start")
	token, _ := started["session_token"].(string)
	if token == "" || !strings.Contains(started["pointer_url"].(string), "/i/"+token) {
		t.Fatalf("the page was given no pointer for the person: %v", started)
	}
	// The page did not name an audience; the Identity Agent took it from the
	// Origin the browser sent, and signed the challenge for it.
	w.org.challengeMu.Lock()
	bundle := w.org.challenges[token]
	w.org.challengeMu.Unlock()
	if bundle.Audience != aPagesOrigin {
		t.Fatalf("the challenge is for %q, not for the page that asked (%s)", bundle.Audience, aPagesOrigin)
	}
	if got := page.say(t, "poll"); got["state"] != "pending" {
		t.Fatalf("the page signed somebody in before anybody answered: %v", got)
	}

	h := aPersonsIdentityAgent(t)
	req := login.StartLoginRequest{SessionToken: token, RPSessionURL: ia.URL}
	preview, err := h.Preview(req)
	if err != nil {
		t.Fatalf("the person's Identity Agent refused the site the organisation signed: %v", err)
	}
	if _, err := h.Approve(req); err != nil {
		t.Fatalf("an approved sign-in was not admitted: %v", err)
	}

	// The page is handed the assertion and checks it itself: the person's key
	// log is checked by the Identity Agent at its public login route.
	got := page.say(t, "poll")
	if got["state"] != "signed-in" || got["pairwise_aid"] != preview.PairwiseAID || got["claimed_by_agent"] != preview.PairwiseAID {
		t.Fatalf("the page signed in %v, not the person who answered (%s)", got, preview.PairwiseAID)
	}
	// The same assertion presented to the page's check again is spent.
	if again := page.say(t, "poll-again"); again["valid"] != false || !strings.Contains(again["reason"].(string), "already used") {
		t.Fatalf("a replayed assertion was not refused as spent: %v", again)
	}
	// The Identity Agent handed the identity over once. Asking again yields none.
	if third := page.say(t, "poll"); third["state"] != "withheld" {
		t.Fatalf("the identity was handed over twice: %v", third)
	}
}

func TestAPageSignsInToItsOwnOriginOnly(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	ia := anOrganisationsAgentOnTheOpenInternet(t, w)
	start := func(origin, body string) (int, string) {
		req, _ := http.NewRequest("POST", ia.URL+"/api/login/session/the-website", strings.NewReader(body))
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// A page cannot ask for a sign-in to another page's origin, or to none.
	if code, _ := start(aPagesOrigin, `{"audience":"https://victim.example"}`); code != http.StatusBadRequest {
		t.Errorf("a page asked for a sign-in to another origin and got %d", code)
	}
	if code, _ := start("null", `{}`); code != http.StatusBadRequest {
		t.Errorf("a page with no origin was given a sign-in (%d)", code)
	}
	// A server asking, with no Origin, names its own audience as before.
	if code, body := start("", `{"audience":"https://portal.example"}`); code != http.StatusOK {
		t.Errorf("a server could not start a sign-in: %d %s", code, body)
	}

	// An asset that names the origin of its website is not signed in to from
	// another page.
	a, ok, err := w.org.assetHandler.Store.GetAsset("the-website")
	if err != nil || !ok {
		t.Fatalf("no asset: %v", err)
	}
	a.Origin = aPagesOrigin + "/"
	if err := w.org.assetHandler.Store.UpsertAsset(a); err != nil {
		t.Fatal(err)
	}
	if code, _ := start("https://elsewhere.example", `{}`); code != http.StatusForbidden {
		t.Errorf("another page signed in to this website's asset (%d)", code)
	}
	if code, body := start("https://PORTAL.example", `{}`); code != http.StatusOK {
		t.Errorf("the website's own page was refused: %d %s", code, body)
	}
}

// Only the one who started a sign-in is handed the assertion with the identity,
// and only once; anybody else holding the token learns nothing.
func TestOnlyTheStarterIsHandedTheAssertion(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	ia := anOrganisationsAgentOnTheOpenInternet(t, w)
	req, _ := http.NewRequest("POST", ia.URL+"/api/login/session/the-website", strings.NewReader(`{}`))
	req.Header.Set("Origin", aPagesOrigin)
	var started struct {
		Token  string `json:"session_token"`
		Secret string `json:"collector_secret"`
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&started)
	resp.Body.Close()

	h := aPersonsIdentityAgent(t)
	sr := login.StartLoginRequest{SessionToken: started.Token, RPSessionURL: ia.URL}
	if _, err := h.Preview(sr); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Approve(sr); err != nil {
		t.Fatal(err)
	}
	read := func(secret string) map[string]any {
		r, _ := http.NewRequest("GET", ia.URL+"/api/login/session/the-website/"+started.Token, nil)
		if secret != "" {
			r.Header.Set("X-Collector-Secret", secret)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}
	if out := read(""); out["assertion"] != nil || out["app_session_token"] != nil {
		t.Fatalf("somebody without the secret was handed the sign-in: %v", out)
	}
	out := read(started.Secret)
	w.org.challengeMu.Lock()
	b := w.org.challenges[started.Token]
	w.org.challengeMu.Unlock()
	if out["assertion"] == nil || out["nonce"] != b.Nonce || out["site_aid"] != b.SiteAID {
		t.Fatalf("the starter was not handed the assertion with its nonce and site: %v", out)
	}
	if again := read(started.Secret); again["assertion"] != nil || again["identity_withheld"] != true {
		t.Fatalf("the assertion was handed over twice: %v", again)
	}
}

// The key-check route answers a page's browser, and only that: its answers
// carry the header whether they admit or refuse, so a page can read why.
func TestAPageCanReadTheKeyCheck(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentOpen})
	ia := anOrganisationsAgentOnTheOpenInternet(t, w)
	pre, _ := http.NewRequest("OPTIONS", ia.URL+"/public/login/key", nil)
	pre.Header.Set("Origin", aPagesOrigin)
	pre.Header.Set("Access-Control-Request-Method", "POST")
	pre.Header.Set("Access-Control-Request-Headers", "content-type")
	resp, err := http.DefaultClient.Do(pre)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 || resp.Header.Get("Access-Control-Allow-Origin") == "" ||
		!strings.Contains(strings.ToLower(resp.Header.Get("Access-Control-Allow-Headers")), "content-type") {
		t.Fatalf("the preflight did not let a page post JSON: %d %v", resp.StatusCode, resp.Header)
	}
	post, _ := http.NewRequest("POST", ia.URL+"/public/login/key", strings.NewReader(`{"aid":"EX","key_log":"not a log"}`))
	post.Header.Set("Origin", aPagesOrigin)
	post.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		t.Fatalf("a made-up key log established a key (%d)", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") == "" {
		t.Fatal("a refusal could not be read by the page")
	}
}

// anOrganisationsAgentOnTheOpenInternet is the organisation's Identity Agent as
// a page and a person reach it: the routes a site and a person's agent use,
// with the public routes mounted as they are in use.
func anOrganisationsAgentOnTheOpenInternet(t *testing.T, w *aWebsiteWorld) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	r.Get("/public/oobi/{aid}", w.org.handleOobiServe)
	r.Get("/i/{token}", w.org.handleChallengeBundleServe)
	w.org.mountLoginWidgetRoutes(r)
	w.org.mountPublicDidWebsRoutes(r)
	r.Post("/api/login/callback", w.org.handleLoginCallback)
	// The agent names itself https unless told otherwise, as it is behind TLS in
	// use; this one is reached over plain HTTP on the loopback.
	ia := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, rq *http.Request) {
		rq.Header.Set("X-Forwarded-Proto", "http")
		r.ServeHTTP(rw, rq)
	}))
	t.Cleanup(ia.Close)
	return ia
}

type aPageDriver struct {
	in  io.WriteCloser
	out *bufio.Reader
}

// say sends the page one command and returns what it printed.
func (p *aPageDriver) say(t *testing.T, command string) map[string]any {
	t.Helper()
	if _, err := io.WriteString(p.in, command+"\n"); err != nil {
		t.Fatal(err)
	}
	line, err := p.out.ReadString('\n')
	if err != nil {
		t.Fatalf("the page said nothing to %q: %v", command, err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatalf("the page said %q", line)
	}
	if e, bad := out["error"]; bad {
		t.Fatalf("the page failed at %q: %v", command, e)
	}
	return out
}

func startAPageWithOnlyTheSDK(t *testing.T, iaURL, assetID, origin string) *aPageDriver {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed, so the login SDK cannot run as a third party's page")
	}
	web := filepath.Join("..", "..", "packages", "login-web")
	for _, built := range []string{
		filepath.Join(web, "dist", "page.js"),
		filepath.Join("..", "..", "packages", "login-verify", "dist", "browser.js"),
	} {
		if _, err := os.Stat(built); err != nil {
			t.Skipf("%s is not built: run `npm ci && npm run build` in packages/login-verify and packages/login-web", built)
		}
	}
	cmd := exec.Command(node, filepath.Join(web, "src", "a-page-with-only-the-sdk.mjs"))
	cmd.Env = append(os.Environ(), "IA_URL="+iaURL, "ASSET_ID="+assetID, "ORIGIN="+origin)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	p := &aPageDriver{in: in, out: bufio.NewReader(out)}
	if line, err := p.out.ReadString('\n'); err != nil || !strings.Contains(line, "ready") {
		t.Fatalf("the stand-in page did not start: %q %v", line, err)
	}
	return p
}
