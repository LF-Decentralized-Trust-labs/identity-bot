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
	"identity-agent-core/brainsignin"
	"identity-agent-core/githubapp"
	"identity-agent-core/lending"
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
	// duringMint, when set, runs while GitHub is making a token, before it
	// answers: something changing meanwhile.
	duringMint func()
}

type minted struct {
	Token        string
	Repositories []string
	Permissions  map[string]string
}

// repoIDs are GitHub's numbers for the stand-in's repositories.
var repoIDs = map[string]int64{"acme/docs": 101, "acme/sandbox": 102, "acme/site": 103}

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
				RepositoryIDs []int64           `json:"repository_ids"`
				Permissions   map[string]string `json:"permissions"`
			}
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &q)
			g.mu.Lock()
			hook := g.duringMint
			g.mu.Unlock()
			if hook != nil && len(q.RepositoryIDs) > 0 {
				hook()
			}
			g.mu.Lock()
			g.n++
			tok := fmt.Sprintf("ghs_LENT_TOKEN_%03d", g.n)
			full := []map[string]any{}
			var names []string
			for _, id := range q.RepositoryIDs {
				for name, n := range repoIDs {
					if n == id {
						full = append(full, map[string]any{"id": id, "full_name": name})
						names = append(names, name)
					}
				}
			}
			sort.Strings(names)
			g.made = append(g.made, minted{Token: tok, Repositories: names, Permissions: q.Permissions})
			g.mu.Unlock()
			selection := "selected"
			if len(q.RepositoryIDs) == 0 {
				selection = "all"
			}
			reply(201, map[string]any{"token": tok, "expires_at": time.Now().Add(time.Hour).UTC(),
				"permissions": q.Permissions, "repositories": full, "repository_selection": selection})
		case r.Method == "GET" && r.URL.Path == "/installation/repositories":
			var out []map[string]any
			for _, x := range reachable {
				out = append(out, map[string]any{"id": repoIDs[x], "full_name": x, "private": true})
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

// tokenFor is the token made for exactly these repositories, at this access.
func (g *gitHub) tokenFor(t *testing.T, access string, repos ...string) string {
	t.Helper()
	sort.Strings(repos)
	for _, m := range g.lentTokens() {
		if reflect.DeepEqual(m.Repositories, repos) && (m.Permissions["contents"] == access) {
			return m.Token
		}
	}
	t.Fatalf("no %s token was made for %v: %+v", access, repos, g.lentTokens())
	return ""
}

// githubLends are the GitHub lends the ledger remembers, open or still to
// withdraw.
func githubLends(t *testing.T, w *talkWorld) []lending.Lend {
	t.Helper()
	all, err := w.s.lends().All()
	if err != nil {
		t.Fatal(err)
	}
	var out []lending.Lend
	for _, l := range all {
		if l.Kind == lendGitHub {
			out = append(out, l)
		}
	}
	return out
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
// by GitHub's numbers for them, with exactly that access's permissions: one
// token for what it may write, and one that reads every repository it may use,
// since it may only read some. A repository it was not granted is refused, and
// so is one the App cannot reach.
func TestATokenIsLimitedToExactlyTheGrantedRepositories(t *testing.T) {
	w, g := githubWorld(t)
	w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"}, [2]string{"Acme/Docs", "read"})
	code, out, raw := w.asOwner(t, "GET", "/api/mcp/agents/"+w.a.ID+"/github", "")
	if code != http.StatusOK || !strings.Contains(raw, `{"repository":"acme/docs","id":101,"access":"read"}`) ||
		!strings.Contains(raw, `{"repository":"acme/sandbox","id":102,"access":"write"}`) {
		t.Fatalf("the grant is not as set: %d %s", code, raw)
	}
	_ = out
	lent, err := w.hostA.BorrowGitHub(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	made := g.lentTokens()
	sort.Slice(made, func(i, j int) bool { return len(made[i].Repositories) > len(made[j].Repositories) })
	if len(made) != 2 ||
		!reflect.DeepEqual(made[0].Repositories, []string{"acme/docs", "acme/sandbox"}) ||
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

// The token reaches the brain through its environment only: gh's GH_TOKEN —
// the token that reads every repository it may use, since it may only read
// some — and git's credential helper reading them from there: the write token
// for the repository it may write, the read token for the one it may read,
// nothing for any other. Not its arguments, not a file, and not a token somebody exported
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
		write, read := g.tokenFor(t, "write", "acme/sandbox"), g.tokenFor(t, "read", "acme/docs", "acme/sandbox")
		for _, want := range []string{
			"GH:" + read + "\n",
			"acme_sandbox:password=" + write + "\n",
			"acme_docs:password=" + read + "\n",
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
		if n := len(githubLends(t, w)); n != 0 {
			t.Fatalf("fail=%v: %d lend(s) still held after the run", fail, n)
		}
	}
}

// Revoking the AI agent withdraws, at GitHub, every token it was lent that
// has not lapsed — at once, not when it would expire. So do removing the
// machine as its body and disconnecting the App. Narrowing its grant
// withdraws only the token that gave what was taken away; a change that takes
// nothing away withdraws nothing.
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
		write, read := g.tokenFor(t, "write", "acme/sandbox"), g.tokenFor(t, "read", "acme/docs", "acme/sandbox")
		// Write becomes read: the write token goes, the read one stays.
		w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "read"}, [2]string{"acme/docs", "read"})
		if !g.wasRevoked(write) || g.wasRevoked(read) {
			t.Fatalf("narrowing write to read: write withdrawn %v, read withdrawn %v", g.wasRevoked(write), g.wasRevoked(read))
		}
		if l := githubLends(t, w); len(l) != 1 || !l[0].IsOpen(time.Now()) {
			t.Fatalf("the run lost its read access: %+v", l)
		}
		// A repository taken away: the token that reads it goes too.
		w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "read"})
		if !g.wasRevoked(read) {
			t.Fatal("the token for a repository taken away was not withdrawn")
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
		b, ok := w.s.bodies().ActiveByHost(githubLends(t, w)[0].Host)
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
	if l := githubLends(t, w); len(l) != 1 || !l[0].Returned || len(l[0].Withdrawing) != 1 {
		t.Fatalf("a token GitHub was not reached to withdraw was forgotten: %+v", l)
	}
	w.s.githubAPI = g.srv.URL
	w.s.endLendsNoLongerGranted("test")
	if !g.wasRevoked(g.lentTokens()[0].Token) || len(githubLends(t, w)) != 0 {
		t.Fatal("the withdrawal was not tried again")
	}
}

// A browser session can neither connect nor disconnect the App, list what it
// reaches, nor grant an AI agent repositories: the App's key makes tokens for
// the organisation's repositories, and a grant outlives the session. Each is
// asked with a live session the owner granted, which reaches what a session
// may — and is refused these. A request that is no one's connects nothing.
func TestABrowserSessionCannotConnectTheGitHubApp(t *testing.T) {
	w := signInWorld(t)
	g := newGitHub(t)
	w.s.githubAPI = g.srv.URL
	w.s.BrowserSessions = newBrowserSessions()
	const secret = "a-secret-only-the-browser-has"
	id, code, _, err := w.s.BrowserSessions.newChallenge(hashSecret(secret))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.s.BrowserSessions.grant(code); err != nil {
		t.Fatal(err)
	}
	session, _, err := w.s.BrowserSessions.claim(id, secret)
	if err != nil {
		t.Fatal(err)
	}
	asSession := func(method, path, body string) int {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+session)
		rec := httptest.NewRecorder()
		w.s.router.ServeHTTP(rec, r)
		return rec.Code
	}
	if c := asSession("GET", "/api/github", ""); c != http.StatusOK {
		t.Fatalf("the session is not one the Identity Agent takes: %d", c)
	}
	connect, _ := json.Marshal(map[string]any{"app_id": 42, "installation_id": 7, "private_key": g.pem})
	for _, q := range [][3]string{
		{"PUT", "/api/github", string(connect)},
		{"DELETE", "/api/github", ""},
		{"GET", "/api/github/repositories", ""},
		{"PUT", "/api/mcp/agents/" + w.a.ID + "/github", `{"repositories":[{"repository":"acme/sandbox","access":"write"}]}`},
	} {
		if c := asSession(q[0], q[1], q[2]); c != http.StatusForbidden {
			t.Errorf("a browser session reached %s %s: %d", q[0], q[1], c)
		}
	}
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, httptest.NewRequest("PUT", "/api/github", bytes.NewReader(connect)))
	if rec.Code == http.StatusOK {
		t.Fatal("a request that is not the owner's connected the App")
	}
	if _, had, _ := w.s.githubConnection(); had {
		t.Fatal("the App was kept")
	}
	if len(g.lentTokens()) != 0 {
		t.Fatal("a token was made")
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

// A grant that changes while GitHub is making the tokens — before anything
// is recorded for the sweep to find — does not get them handed over: the lend
// is checked again once recorded, refused, and its tokens withdrawn.
func TestAGrantThatChangesWhileGitHubMintsIsNotLent(t *testing.T) {
	w, g := githubWorld(t)
	w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"})
	g.mu.Lock()
	g.duringMint = func() {
		g.mu.Lock()
		g.duringMint = nil
		g.mu.Unlock()
		w.grantRepos(t, w.a.ID)
	}
	g.mu.Unlock()
	if _, err := w.hostA.BorrowGitHub(context.Background()); err == nil {
		t.Fatal("access the grant no longer gives was handed over")
	}
	made := g.lentTokens()
	if len(made) != 1 || !g.wasRevoked(made[0].Token) {
		t.Fatalf("the token made while the grant changed was not withdrawn: %+v", made)
	}
	if n := len(githubLends(t, w)); n != 0 {
		t.Fatalf("%d lend(s) left", n)
	}
}

// What cannot be checked is not lent: when the organisation's App cannot be
// read once the lend is recorded, it is withdrawn and refused. And a lend
// whose App cannot be read later is withdrawn by the next sweep.
func TestALendThatCannotBeCheckedIsWithdrawn(t *testing.T) {
	w, g := githubWorld(t)
	w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"})
	var conn githubapp.Connection
	if _, err := w.s.SandboxManager.Kept(githubAppRef, keptGitHubApp, &conn); err != nil {
		t.Fatal(err)
	}
	unreadable := func() {
		if err := w.s.SandboxManager.SetKept(githubAppRef, "not-a-github-app", map[string]int{"x": 1}); err != nil {
			t.Fatal(err)
		}
	}
	g.mu.Lock()
	g.duringMint = func() { g.mu.Lock(); g.duringMint = nil; g.mu.Unlock(); unreadable() }
	g.mu.Unlock()
	if _, err := w.hostA.BorrowGitHub(context.Background()); err == nil {
		t.Fatal("access was handed over though the App could not be read to check it")
	}
	if made := g.lentTokens(); len(made) != 1 || !g.wasRevoked(made[0].Token) {
		t.Fatalf("not withdrawn: %+v", made)
	}
	// Later: lent while the App could be read, then it cannot.
	if err := w.s.SandboxManager.SetKept(githubAppRef, keptGitHubApp, conn); err != nil {
		t.Fatal(err)
	}
	if _, err := w.hostA.BorrowGitHub(context.Background()); err != nil {
		t.Fatal(err)
	}
	unreadable()
	w.s.endLendsNoLongerGranted("test")
	if made := g.lentTokens(); !g.wasRevoked(made[len(made)-1].Token) {
		t.Fatal("a lend whose App cannot be read was left standing")
	}
}

// A body holds one GitHub lend at a time: borrowing again withdraws what it
// held, and a body that starts again gives back whatever it held before.
func TestABodyHoldsOneGitHubLendAtATime(t *testing.T) {
	w, g := githubWorld(t)
	w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"})
	ctx := context.Background()
	if _, err := w.hostA.BorrowGitHub(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := w.hostA.BorrowGitHub(ctx); err != nil {
		t.Fatal(err)
	}
	made := g.lentTokens()
	if len(made) != 2 || !g.wasRevoked(made[0].Token) || g.wasRevoked(made[1].Token) {
		t.Fatalf("borrowing again: first withdrawn %v, second withdrawn %v", g.wasRevoked(made[0].Token), g.wasRevoked(made[1].Token))
	}
	if err := w.hostA.ReturnEveryGitHub(ctx); err != nil {
		t.Fatal(err)
	}
	if !g.wasRevoked(made[1].Token) || len(githubLends(t, w)) != 0 {
		t.Fatal("what a body held before it started again was not withdrawn")
	}
	// Nothing held: nothing to give back, and no error.
	if err := w.hostA.ReturnEveryGitHub(ctx); err != nil {
		t.Fatal(err)
	}
}

// Replacing the App — even with the same App and installation, only a new
// key — withdraws everything lent under the one it replaces; and a lend names
// the App that made it, so one made by an App no longer connected is
// withdrawn by the next sweep.
func TestReplacingTheAppWithdrawsWhatItLent(t *testing.T) {
	w, g := githubWorld(t)
	w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"})
	if _, err := w.hostA.BorrowGitHub(context.Background()); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"app_id": 42, "installation_id": 7, "private_key": g.pem})
	if code, _, raw := w.asOwner(t, "PUT", "/api/github", string(body)); code != http.StatusOK {
		t.Fatalf("replacing the key: %d %s", code, raw)
	}
	if !g.wasRevoked(g.lentTokens()[0].Token) {
		t.Fatal("replacing the App's key left what it lent standing")
	}
	if _, err := w.hostA.BorrowGitHub(context.Background()); err != nil {
		t.Fatal(err)
	}
	var conn githubapp.Connection
	if _, err := w.s.SandboxManager.Kept(githubAppRef, keptGitHubApp, &conn); err != nil {
		t.Fatal(err)
	}
	conn.InstallationID = 8
	if err := w.s.SandboxManager.SetKept(githubAppRef, keptGitHubApp, conn); err != nil {
		t.Fatal(err)
	}
	w.s.endLendsNoLongerGranted("test")
	if made := g.lentTokens(); !g.wasRevoked(made[len(made)-1].Token) {
		t.Fatal("a lend made under another installation was left standing")
	}
}

// Write refused by the one check — the capability turned off here — leaves
// the AI agent the read access its grant gives, for the same repositories.
func TestARefusedWriteKeepsRead(t *testing.T) {
	w, g := githubWorld(t)
	w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"}, [2]string{"acme/docs", "read"})
	rec, err := w.s.SandboxManager.Store().GetCapabilityRecord(capabilityRepoWrite)
	if err != nil || rec == nil {
		t.Fatalf("the write capability: %v %v", rec, err)
	}
	rec.Enabled = false
	if err := w.s.SandboxManager.Store().UpsertCapabilityRecord(*rec); err != nil {
		t.Fatal(err)
	}
	lent, err := w.hostA.BorrowGitHub(context.Background())
	if err != nil {
		t.Fatalf("read access was lost with write: %v", err)
	}
	made := g.lentTokens()
	if len(made) != 1 || made[0].Permissions["contents"] != "read" ||
		!reflect.DeepEqual(made[0].Repositories, []string{"acme/docs", "acme/sandbox"}) {
		t.Fatalf("GitHub was asked for: %+v", made)
	}
	_ = w.hostA.ReturnGitHub(context.Background(), lent)
}

// Revoking an AI agent ends every kind of lend at once: its brain's lease
// stops holding a place and cannot be renewed, as well as its GitHub tokens
// being withdrawn.
func TestRevokingAnAIAgentEndsItsBrainLeaseAtOnce(t *testing.T) {
	w, _ := githubWorld(t)
	w.grantRepos(t, w.a.ID, [2]string{"acme/sandbox", "write"})
	if code, _, raw := w.asOwner(t, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in",
		`{"kind":"api_key","provider":"anthropic","secret":"sk-ant-api03-A-KEY","max_concurrent_runs":1}`); code != http.StatusOK {
		t.Fatalf("signing in: %d %s", code, raw)
	}
	b, err := w.hostA.Borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	inUse := func() int { return w.s.brainRunsInUse(func(x lending.Lend) bool { return x.Agent == w.a.ID }) }
	if inUse() != 1 {
		t.Fatal("the lease does not hold")
	}
	// A sweep leaves a lease its grant still covers.
	w.s.endLendsNoLongerGranted("test")
	if inUse() != 1 {
		t.Fatal("a sweep ended a lease the AI agent's grant still covers")
	}
	grant := w.s.findCapabilityGrant(w.a.PairwiseAID)
	if code, _, raw := w.asOwner(t, "POST", "/api/credentials/"+grant.SAID+"/revoke", ""); code != http.StatusOK {
		t.Fatalf("revoking: %d %s", code, raw)
	}
	if n := inUse(); n != 0 {
		t.Fatalf("a revoked AI agent's lease still holds %d place(s)", n)
	}
	if err := w.hostA.Renew(context.Background(), b); err == nil {
		t.Fatal("a revoked AI agent's lease was renewed")
	}
	if n := len(governanceRows(t, w, "agent.brain.sign_in.ended")); n != 1 {
		t.Fatalf("%d endings recorded", n)
	}
}

// Leases kept in their own file by a version before this one are moved into
// the one record, once, and their file removed.
func TestLeasesKeptBeforeAreMovedIntoTheOneRecord(t *testing.T) {
	w := signInWorld(t)
	now := time.Now().UTC()
	lapsed := now.Add(-time.Hour)
	old, _ := json.Marshal([]brainsignin.LegacyLease{
		{ID: "bl_held", Agent: w.a.ID, Host: "h1", Pool: "acct", Lent: "fp", LentAt: now, Expires: now.Add(time.Minute)},
		{ID: "bl_lapsed", Agent: w.a.ID, Host: "h2", LentAt: lapsed, Expires: lapsed, LapsedAt: &lapsed},
	})
	file := filepath.Join(w.s.DataDir, "brain_sign_in_leases.json")
	if err := os.WriteFile(file, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if n := w.s.brainRunsInUse(func(x lending.Lend) bool { return x.Pool == "acct" }); n != 1 {
		t.Fatalf("%d runs of the account in use after moving, want 1", n)
	}
	if _, ok, _ := w.s.lends().Find(lendBrainSignIn, "bl_lapsed", "h2", w.a.ID, now); !ok {
		t.Fatal("a lapsed lease kept to be given back was not moved")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("the old file was left")
	}
}
