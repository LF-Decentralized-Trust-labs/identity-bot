package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"identity-agent-core/agenthost"
)

// gitHub is a stand-in for GitHub's API: one App (42, "acme-agents"), one
// installation (7) on the account acme, which can reach three repositories.
// It checks every statement the App signs against the App's public key, and
// records the tokens it made and the ones withdrawn.
type gitHub struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	pem  string
	mu   sync.Mutex
	made []minted
	// revoked are the tokens withdrawn, in order.
	revoked []string
	n       int
}

type minted struct {
	Token        string
	Repositories []string
	Permissions  map[string]string
}

func newGitHub(t *testing.T) *gitHub {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	g := &gitHub{key: k, pem: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k)}))}
	reachable := []string{"acme/docs", "acme/sandbox", "acme/site"}
	asApp := func(r *http.Request) bool {
		parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
		if len(parts) != 3 {
			return false
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		return rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, d[:], sig) == nil
	}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply := func(code int, v any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/app":
			if !asApp(r) {
				reply(401, map[string]string{"message": "A JSON web token could not be decoded"})
				return
			}
			reply(200, map[string]any{"id": 42, "slug": "acme-agents", "name": "Acme agents"})
		case r.Method == "GET" && r.URL.Path == "/app/installations/7":
			if !asApp(r) {
				reply(401, nil)
				return
			}
			reply(200, map[string]any{"id": 7, "account": map[string]string{"login": "Acme"}})
		case r.Method == "GET" && r.URL.Path == "/users/acme-agents[bot]":
			reply(200, map[string]any{"id": 9})
		case r.Method == "POST" && r.URL.Path == "/app/installations/7/access_tokens":
			if !asApp(r) {
				reply(401, nil)
				return
			}
			var q struct {
				Repositories []string          `json:"repositories"`
				Permissions  map[string]string `json:"permissions"`
			}
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &q)
			g.mu.Lock()
			g.n++
			tok := fmt.Sprintf("ghs_LENT_TOKEN_%03d", g.n)
			full := []map[string]string{}
			var names []string
			for _, name := range q.Repositories {
				full = append(full, map[string]string{"full_name": "acme/" + name})
				names = append(names, "acme/"+name)
			}
			g.made = append(g.made, minted{Token: tok, Repositories: names, Permissions: q.Permissions})
			g.mu.Unlock()
			reply(201, map[string]any{"token": tok, "expires_at": time.Now().Add(time.Hour).UTC(),
				"permissions": q.Permissions, "repositories": full})
		case r.Method == "GET" && r.URL.Path == "/installation/repositories":
			var out []map[string]any
			for _, x := range reachable {
				out = append(out, map[string]any{"full_name": x, "private": true})
			}
			reply(200, map[string]any{"total_count": len(out), "repositories": out})
		case r.Method == "DELETE" && r.URL.Path == "/installation/token":
			g.mu.Lock()
			g.revoked = append(g.revoked, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			g.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(g.srv.Close)
	return g
}

// lentTokens are the tokens made for runs: those asked for named
// repositories, not the ones made only to list them.
func (g *gitHub) lentTokens() []minted {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []minted
	for _, m := range g.made {
		if len(m.Repositories) > 0 {
			out = append(out, m)
		}
	}
	return out
}

func (g *gitHub) wasRevoked(tok string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, x := range g.revoked {
		if x == tok {
			return true
		}
	}
	return false
}

// githubWorld is a signed-in world whose Identity Agent talks to a stand-in
// GitHub, with the organisation's App connected.
func githubWorld(t *testing.T) (*talkWorld, *gitHub) {
	t.Helper()
	w := signInWorld(t)
	g := newGitHub(t)
	w.s.githubAPI = g.srv.URL
	body, _ := json.Marshal(map[string]any{"app_id": 42, "installation_id": 7, "private_key": g.pem})
	code, out, raw := w.asOwner(t, "PUT", "/api/github", string(body))
	if code != http.StatusOK || out["account"] != "acme" || out["commits_as"] != "acme-agents[bot]" {
		t.Fatalf("connecting the App: %d %s", code, raw)
	}
	return w, g
}

func (w *talkWorld) grantRepos(t *testing.T, id string, repos ...[2]string) {
	t.Helper()
	var list []map[string]string
	for _, r := range repos {
		list = append(list, map[string]string{"repository": r[0], "access": r[1]})
	}
	body, _ := json.Marshal(map[string]any{"repositories": append([]map[string]string{}, list...)})
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+id+"/github", string(body)); code != http.StatusOK {
		t.Fatalf("granting repositories: %d %s", code, raw)
	}
}

// An AI agent whose grant gives it no repository is lent nothing, and GitHub
// is not asked for a token for it.
func TestAnAIAgentWithNoRepositoryGrantIsLentNothing(t *testing.T) {
	w, g := githubWorld(t)
	if _, err := w.hostA.BorrowGitHub(context.Background()); !errors.Is(err, agenthost.ErrNoGitHub) {
		t.Fatalf("an AI agent with no repositories: %v", err)
	}
	if n := len(g.lentTokens()); n != 0 {
		t.Fatalf("%d token(s) were made for an AI agent with no grant", n)
	}
	// The lending route takes only a sealed, signed request from a live body.
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, httptest.NewRequest("POST", "/api/agent-host/github", strings.NewReader("{}")))
	if rec.Code == http.StatusOK {
		t.Fatal("GitHub access was lent to a request that is not a body's")
	}
}

// The token is asked of GitHub for exactly the repositories the grant gives,
// with exactly that access's permissions: one token for what it may write,
// one for what it may only read. A repository it was not granted is refused,
// and so is one the App cannot reach.
func TestATokenIsLimitedToExactlyTheGrantedRepositories(t *testing.T) {
	w, g := githubWorld(t)
	w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"}, [2]string{"Acme/Docs", "read"})
	code, out, raw := w.asOwner(t, "GET", "/api/mcp/agents/"+w.a.ID+"/github", "")
	if code != http.StatusOK || !strings.Contains(raw, `{"repository":"acme/docs","access":"read"}`) ||
		!strings.Contains(raw, `{"repository":"acme/sandbox","access":"write"}`) {
		t.Fatalf("the grant is not as set: %d %s", code, raw)
	}
	_ = out
	lent, err := w.hostA.BorrowGitHub(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	made := g.lentTokens()
	sort.Slice(made, func(i, j int) bool { return made[i].Repositories[0] < made[j].Repositories[0] })
	if len(made) != 2 ||
		!reflect.DeepEqual(made[0].Repositories, []string{"acme/docs"}) ||
		!reflect.DeepEqual(made[0].Permissions, map[string]string{"contents": "read", "metadata": "read"}) ||
		!reflect.DeepEqual(made[1].Repositories, []string{"acme/sandbox"}) ||
		!reflect.DeepEqual(made[1].Permissions, map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"}) {
		t.Fatalf("GitHub was asked for: %+v", made)
	}
	if err := w.hostA.ReturnGitHub(context.Background(), lent); err != nil {
		t.Fatal(err)
	}
	for _, m := range made {
		if !g.wasRevoked(m.Token) {
			t.Fatalf("%s was not withdrawn when it was returned", m.Repositories)
		}
	}
	if n := len(governanceRows(t, w, "agent.github.lent")); n != 1 {
		t.Fatalf("%d lends recorded", n)
	}
	if n := len(governanceRows(t, w, "agent.github.returned")); n != 1 {
		t.Fatalf("%d returns recorded", n)
	}
	// A repository the App cannot reach is not granted.
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/github",
		`{"repositories":[{"repository":"acme/secret","access":"read"}]}`); code != http.StatusBadRequest {
		t.Fatalf("granting a repository the App cannot reach: %d %s", code, raw)
	}
	// Another AI agent's body cannot return what this one was lent.
	again, err := w.hostA.BorrowGitHub(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.hostB.ReturnGitHub(context.Background(), &agenthost.LentGitHub{LendID: again.LendID}); err == nil {
		t.Fatal("another body returned a lend it does not hold")
	}
	_ = w.hostA.ReturnGitHub(context.Background(), again)
}

// fakeBrainUsingGit stands in for Claude Code: it writes down its arguments
// and GH_TOKEN, then asks git — through git's own credential machinery, as a
// clone or push would — for the credentials of three repositories.
func fakeBrainUsingGit(t *testing.T, fail bool) (path, record string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in program is a shell script")
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	record = filepath.Join(dir, "record")
	path = filepath.Join(dir, "claude")
	ask := func(repo string) string {
		return "printf 'protocol=https\\nhost=github.com\\npath=" + repo + ".git\\n\\n' | " + git +
			" credential fill 2>/dev/null | sed 's/^/" + strings.ReplaceAll(repo, "/", "_") + ":/' >> " + record + "\n"
	}
	script := "#!/bin/sh\ncat >/dev/null\nfor a in \"$@\"; do printf 'ARG:%s\\n' \"$a\" >> " + record + "; done\n" +
		"printf 'GH:%s\\n' \"$GH_TOKEN\" >> " + record + "\n" +
		"printf 'AUTHOR:%s <%s>\\n' \"$GIT_AUTHOR_NAME\" \"$GIT_AUTHOR_EMAIL\" >> " + record + "\n" +
		ask("acme/sandbox") + ask("acme/docs") + ask("acme/site")
	if fail {
		script += "echo 'it went wrong' >&2\nexit 1\n"
	} else {
		script += "echo '{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"done\",\"session_id\":\"s\",\"modelUsage\":{}}'\n"
	}
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, record
}

// The token reaches the brain through its environment only: gh's GH_TOKEN,
// and git's credential helper reading it from there — the write token for the
// repository it may write, the read token for the one it may read, nothing for
// any other. Not its arguments, not a file, and not a token somebody exported
// on the machine. It is returned when the run ends, and when the run fails,
// and withdrawn at GitHub.
func TestGitHubAccessReachesTheBrainOnlyThroughItsEnvironment(t *testing.T) {
	for _, fail := range []bool{false, true} {
		w, g := githubWorld(t)
		t.Setenv("GH_TOKEN", "a-token-somebody-exported-on-this-machine")
		w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"}, [2]string{"acme/docs", "read"})
		w.openedWith(t)
		path, record := fakeBrainUsingGit(t, fail)
		workspace := t.TempDir()
		if err := w.hostA.Run(context.Background(), agenthost.RunOptions{
			Brain: agenthost.ClaudeCode{Path: path}, Once: true, Workspace: workspace}); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(record)
		if err != nil {
			t.Fatalf("the brain never ran: %v", err)
		}
		got := string(b)
		made := g.lentTokens()
		if len(made) != 2 {
			t.Fatalf("fail=%v: %d tokens made", fail, len(made))
		}
		tokenFor := map[string]string{}
		for _, m := range made {
			tokenFor[m.Repositories[0]] = m.Token
		}
		for _, want := range []string{
			"GH:" + tokenFor["acme/sandbox"] + "\n",
			"acme_sandbox:password=" + tokenFor["acme/sandbox"] + "\n",
			"acme_docs:password=" + tokenFor["acme/docs"] + "\n",
			"AUTHOR:Desk assistant <9+acme-agents[bot]@users.noreply.github.com>\n",
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("fail=%v: the brain did not see %q:\n%s", fail, want, got)
			}
		}
		if strings.Contains(got, "acme_site:password") || strings.Contains(got, "a-token-somebody-exported") {
			t.Fatalf("fail=%v: git or gh was given what was not lent:\n%s", fail, got)
		}
		for _, l := range strings.Split(got, "\n") {
			if strings.HasPrefix(l, "ARG:") && strings.Contains(l, "ghs_") {
				t.Fatalf("a token went on the command line: %s", l)
			}
		}
		for _, m := range made {
			noFileHolds(t, workspace, m.Token)
			noFileHolds(t, w.hostA.DataDir, m.Token)
			noFileHolds(t, w.s.DataDir, m.Token)
			if !g.wasRevoked(m.Token) {
				t.Fatalf("fail=%v: the token for %s was not withdrawn at GitHub when the run ended", fail, m.Repositories)
			}
		}
		if n := len(w.s.githubLends()); n != 0 {
			t.Fatalf("fail=%v: %d lend(s) still held after the run", fail, n)
		}
	}
}

// Revoking the AI agent withdraws, at GitHub, every token it was lent that
// has not lapsed — at once, not when it would expire. So does taking a
// repository out of its grant, and removing the machine as its body.
func TestRevokingTheAIAgentWithdrawsWhatItWasLent(t *testing.T) {
	ctx := context.Background()
	t.Run("the AI agent is revoked", func(t *testing.T) {
		w, g := githubWorld(t)
		w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"})
		if _, err := w.hostA.BorrowGitHub(ctx); err != nil {
			t.Fatal(err)
		}
		grant := w.s.findCapabilityGrant(w.a.PairwiseAID)
		if grant == nil {
			t.Fatal("no grant")
		}
		if code, _, raw := w.asOwner(t, "POST", "/api/credentials/"+grant.SAID+"/revoke", ""); code != http.StatusOK {
			t.Fatalf("revoking: %d %s", code, raw)
		}
		if !g.wasRevoked(g.lentTokens()[0].Token) {
			t.Fatal("the token lent to a revoked AI agent was not withdrawn")
		}
		if _, err := w.hostA.BorrowGitHub(ctx); err == nil {
			t.Fatal("a revoked AI agent was lent GitHub access")
		}
		if n := len(governanceRows(t, w, "agent.github.withdrawn")); n != 1 {
			t.Fatalf("%d withdrawals recorded", n)
		}
	})
	t.Run("its grant no longer names the repository", func(t *testing.T) {
		w, g := githubWorld(t)
		w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"}, [2]string{"acme/docs", "read"})
		if _, err := w.hostA.BorrowGitHub(ctx); err != nil {
			t.Fatal(err)
		}
		// Write becomes read: the write token goes, the read one stays.
		w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "read"}, [2]string{"acme/docs", "read"})
		for _, m := range g.lentTokens() {
			if !g.wasRevoked(m.Token) {
				t.Fatalf("the token for %s was not withdrawn when the grant narrowed", m.Repositories)
			}
		}
	})
	t.Run("an unrelated change keeps what was lent", func(t *testing.T) {
		w, g := githubWorld(t)
		w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"})
		if _, err := w.hostA.BorrowGitHub(ctx); err != nil {
			t.Fatal(err)
		}
		w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"}, [2]string{"acme/docs", "read"})
		if g.wasRevoked(g.lentTokens()[0].Token) {
			t.Fatal("a token still granted was withdrawn")
		}
	})
	t.Run("the machine is removed as its body", func(t *testing.T) {
		w, g := githubWorld(t)
		w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"})
		if _, err := w.hostA.BorrowGitHub(ctx); err != nil {
			t.Fatal(err)
		}
		b, ok := w.s.bodies().ActiveByHost(w.s.githubLends()[0].Host)
		if !ok {
			t.Fatal("no body")
		}
		if code, _, raw := w.asOwner(t, "DELETE", "/api/mcp/agents/"+w.a.ID+"/bodies/"+b.ID, ""); code != http.StatusOK {
			t.Fatalf("removing the body: %d %s", code, raw)
		}
		if !g.wasRevoked(g.lentTokens()[0].Token) {
			t.Fatal("the token lent to a removed body was not withdrawn")
		}
	})
	t.Run("the App is disconnected", func(t *testing.T) {
		w, g := githubWorld(t)
		w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"})
		if _, err := w.hostA.BorrowGitHub(ctx); err != nil {
			t.Fatal(err)
		}
		if code, _, raw := w.asOwner(t, "DELETE", "/api/github", ""); code != http.StatusOK {
			t.Fatalf("disconnecting: %d %s", code, raw)
		}
		if !g.wasRevoked(g.lentTokens()[0].Token) {
			t.Fatal("a token was left standing when the App was disconnected")
		}
		if _, err := w.hostA.BorrowGitHub(ctx); !errors.Is(err, agenthost.ErrNoGitHub) {
			t.Fatalf("lent with no App connected: %v", err)
		}
	})
}

// GitHub not answering a withdrawal leaves the lend to be tried again, not
// forgotten: the next check withdraws it.
func TestAWithdrawalGitHubDidNotAnswerIsTriedAgain(t *testing.T) {
	w, g := githubWorld(t)
	w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"})
	lent, err := w.hostA.BorrowGitHub(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	w.s.githubAPI = "http://127.0.0.1:1"
	if err := w.hostA.ReturnGitHub(context.Background(), lent); err != nil {
		t.Fatal(err)
	}
	if l := w.s.githubLends(); len(l) != 1 || !l[0].Returned {
		t.Fatalf("a token GitHub was not reached to withdraw was forgotten: %+v", l)
	}
	w.s.githubAPI = g.srv.URL
	w.s.withdrawLentGitHubAccessNoLongerGranted("test")
	if !g.wasRevoked(g.lentTokens()[0].Token) || len(w.s.githubLends()) != 0 {
		t.Fatal("the withdrawal was not tried again")
	}
}

// A browser session can neither connect nor disconnect the App, list what it
// reaches, nor grant an AI agent repositories: the App's key makes tokens for
// the organisation's repositories, and a grant outlives the session.
func TestABrowserSessionCannotConnectTheGitHubApp(t *testing.T) {
	for _, route := range []string{"PUT /api/github", "DELETE /api/github", "GET /api/github/repositories",
		"PUT /api/mcp/agents/{id}/github"} {
		method, pattern, _ := strings.Cut(route, " ")
		if _, forbidden := requiresTheKeyItself(method, pattern); !forbidden {
			t.Errorf("a browser session can reach %s", route)
		}
	}
	// And a request that is not the owner's connects nothing.
	w := signInWorld(t)
	g := newGitHub(t)
	w.s.githubAPI = g.srv.URL
	body, _ := json.Marshal(map[string]any{"app_id": 42, "installation_id": 7, "private_key": g.pem})
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, httptest.NewRequest("PUT", "/api/github", bytes.NewReader(body)))
	if rec.Code == http.StatusOK {
		t.Fatal("a request that is not the owner's connected the App")
	}
	if _, had, _ := w.s.githubConnection(); had {
		t.Fatal("the App was kept")
	}
}

// Neither the App's key, nor a statement it signed, nor a token lent is in any
// view, in the log, or on disk as it was given.
func TestNothingSecretIsShownOrLogged(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	w, g := githubWorld(t)
	w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"})
	lent, err := w.hostA.BorrowGitHub(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	keyBody := strings.Join(strings.Split(g.pem, "\n")[1:3], "\n")
	secrets := []string{keyBody, g.lentTokens()[0].Token, "eyJhbGciOiJSUzI1NiIs"}
	for _, path := range []string{"/api/github", "/api/github/repositories", "/api/mcp/agents",
		"/api/mcp/agents/" + w.a.ID + "/github", "/api/vault/credentials", "/api/assets/" + w.a.ID} {
		code, _, body := w.asOwner(t, "GET", path, "")
		if code != http.StatusOK {
			t.Fatalf("reading %s: %d %s", path, code, body)
		}
		for _, s := range secrets {
			if strings.Contains(body, s) {
				t.Fatalf("%s shows a secret", path)
			}
		}
	}
	_ = w.hostA.ReturnGitHub(context.Background(), lent)
	for _, s := range secrets {
		if strings.Contains(logged.String(), s) {
			t.Fatalf("the log holds a secret: %q", s)
		}
		noFileHolds(t, w.s.DataDir, s)
	}
	// The vault's own list of what it holds names no GitHub entry: those are
	// managed where they are used, and cannot be removed around it.
	if code, _, _ := w.asOwner(t, "DELETE", "/api/vault/credentials/kept:github-app", ""); code == http.StatusOK {
		t.Fatal("the App's key was removed around the route that withdraws what it lent")
	}
}
