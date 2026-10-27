package agenthost

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

// An AI agent granted GitHub repositories is lent, for each run, a token that
// works only for those repositories, for at most an hour. This machine never
// keeps it. It goes into the brain's environment for that run alone — gh reads
// it from there, and git asks this program for it as a credential helper that
// reads it from the same environment — and is returned when the run ends,
// also when the run fails, so the Identity Agent withdraws it at GitHub.
// Nothing of it is written to disk, and nothing of it goes on a command line.

// LentGitHub is GitHub access lent for one run.
type LentGitHub struct {
	LendID      string
	GitHost     string
	AuthorName  string
	AuthorEmail string
	tokens      []lentToken
}

type lentToken struct {
	Access       string   `json:"access"`
	Repositories []string `json:"repositories"`
	Token        string   `json:"token"`
}

// ErrNoGitHub is an AI agent that uses no GitHub repositories, or whose
// organisation has connected no GitHub App.
var ErrNoGitHub = errors.New("this AI agent is lent no GitHub access")

// BorrowGitHub asks the Identity Agent for GitHub access for one run. It
// returns ErrNoGitHub when the AI agent's grant gives it no repositories, or
// its Identity Agent lends none.
func (h *Host) BorrowGitHub(ctx context.Context) (*LentGitHub, error) {
	code, b, err := h.CallContext(ctx, "POST", "/api/agent-host/github", []byte("{}"))
	if err != nil {
		return nil, err
	}
	var out struct {
		Error       string      `json:"error"`
		NoGitHub    bool        `json:"no_github"`
		LendID      string      `json:"lend_id"`
		GitHost     string      `json:"git_host"`
		AuthorName  string      `json:"author_name"`
		AuthorEmail string      `json:"author_email"`
		Tokens      []lentToken `json:"tokens"`
	}
	_ = json.Unmarshal(b, &out)
	switch {
	case code == http.StatusOK:
	case out.NoGitHub,
		// An Identity Agent from before GitHub access was lent does not know
		// the route: its gate refuses it as not authorised, or nothing answers.
		code == http.StatusMethodNotAllowed, out.Error == "not_authorized",
		code == http.StatusNotFound && out.Error == "":
		return nil, ErrNoGitHub
	default:
		return nil, fmt.Errorf("GitHub access could not be borrowed (%d): %s", code, firstNonEmpty(out.Error, string(b)))
	}
	if out.LendID == "" || len(out.Tokens) == 0 {
		return nil, errors.New("the Identity Agent lent GitHub access with no lend or no token")
	}
	return &LentGitHub{LendID: out.LendID, GitHost: firstNonEmpty(out.GitHost, "github.com"),
		AuthorName: out.AuthorName, AuthorEmail: out.AuthorEmail, tokens: out.Tokens}, nil
}

// ReturnGitHub gives GitHub access back, so the Identity Agent withdraws its
// tokens at GitHub.
func (h *Host) ReturnGitHub(ctx context.Context, g *LentGitHub) error {
	for i := range g.tokens {
		g.tokens[i].Token = ""
	}
	return h.returnGitHub(ctx, map[string]any{"lend_id": g.LendID})
}

// ReturnEveryGitHub gives back whatever GitHub access this body still holds
// from before it started — a run it was in when it stopped — so the Identity
// Agent withdraws it at once rather than when it lapses. An Identity Agent
// that lends no GitHub access, or holds nothing for this body, has nothing to
// take back.
func (h *Host) ReturnEveryGitHub(ctx context.Context) error {
	err := h.returnGitHub(ctx, map[string]any{"every": true})
	if errors.Is(err, ErrLeaseUnknown) || errors.Is(err, errReturnRefused) {
		return nil
	}
	return err
}

func (h *Host) returnGitHub(ctx context.Context, q map[string]any) error {
	body, _ := json.Marshal(q)
	code, out, err := h.CallContext(ctx, "POST", "/api/agent-host/github/return", body)
	if err != nil {
		return err
	}
	if code == http.StatusNotFound && strings.Contains(string(out), "no_lend") {
		return ErrLeaseUnknown
	}
	if code >= 400 && code < 500 {
		return fmt.Errorf("%w (%d): %s", errReturnRefused, code, out)
	}
	if code != http.StatusOK {
		return fmt.Errorf("GitHub access could not be returned (%d): %s", code, out)
	}
	return nil
}

// giveGitHubBack returns GitHub access whatever became of the run, trying
// again while the Identity Agent cannot be reached. If it still cannot be,
// the tokens lapse at GitHub within the hour on their own.
//
// Nothing is kept on this machine to give back later: a GitHub return carries
// nothing but the lend's name, and the Identity Agent withdraws what is not
// returned when its grant ends, when this body starts again, or when the
// tokens lapse.
func (h *Host) giveGitHubBack(g *LentGitHub, logf func(string, ...any)) {
	if err := retryReturn(func(ctx context.Context) error { return h.ReturnGitHub(ctx, g) }); err != nil {
		logf("[agent-host] the run's GitHub access could not be returned: %v; it lapses at GitHub within the hour", err)
	}
}

// The variables the git credential helper reads, as the brain's environment
// carries them.
const (
	envGitHubWriteToken = "AGENT_HOST_GITHUB_WRITE_TOKEN"
	envGitHubWriteRepos = "AGENT_HOST_GITHUB_WRITE_REPOS"
	envGitHubReadToken  = "AGENT_HOST_GITHUB_READ_TOKEN"
	envGitHubReadRepos  = "AGENT_HOST_GITHUB_READ_REPOS"
	envGitHubHost       = "AGENT_HOST_GITHUB_HOST"
)

// githubVars are the variables that carry GitHub access or would change how
// git and gh find it. When a run is lent GitHub access, none of these is
// passed on from this machine's own environment, so neither program falls back
// on a token or a helper somebody set up by hand.
var githubVars = []string{
	"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GH_HOST", "GH_CONFIG_DIR",
	"GIT_ASKPASS", "SSH_ASKPASS", "GIT_TERMINAL_PROMPT", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS",
	"GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL",
	envGitHubWriteToken, envGitHubWriteRepos, envGitHubReadToken, envGitHubReadRepos, envGitHubHost,
}

// githubVarPrefixes are families of variables withheld the same way: git
// reads GIT_CONFIG_KEY_0, GIT_CONFIG_VALUE_0 and so on.
var githubVarPrefixes = []string{"GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"}

// Env is the lent access as the brain's environment. self is this program,
// which git runs as its credential helper.
//
// gh reads GH_TOKEN, one token for every repository: the write token when the
// AI agent may write every repository it uses; otherwise the read token, which
// the Identity Agent makes for every repository it may use — whether or not it
// may write them all — so gh can read all of them. In that case gh cannot push
// or open a pull request; git pushes
// with the write token, and a brain that must open a pull request with gh
// gives it AGENT_HOST_GITHUB_WRITE_TOKEN for that one command.
//
// git asks this program for a token per repository: the write token for one
// it may write, the read token for one it may only read. Every credential
// helper the machine or the brain's user configured is set aside for the run,
// for every host, so git uses nothing else; and an SSH address on GitHub is
// rewritten to HTTPS, so a key in ~/.ssh is not used for GitHub instead of
// what was lent. Commits name the AI agent as author and committer, at the
// GitHub App's address, so GitHub shows them as the App's.
func (g *LentGitHub) Env(self string) []string {
	var env []string
	write, read := "", ""
	writable := map[string]bool{}
	var readable []string
	for _, t := range g.tokens {
		switch t.Access {
		case "write":
			env = append(env, envGitHubWriteToken+"="+t.Token, envGitHubWriteRepos+"="+strings.Join(t.Repositories, ","))
			write = t.Token
			for _, r := range t.Repositories {
				writable[r] = true
			}
		case "read":
			env = append(env, envGitHubReadToken+"="+t.Token, envGitHubReadRepos+"="+strings.Join(t.Repositories, ","))
			read = t.Token
			readable = t.Repositories
		}
	}
	gh := firstNonEmpty(read, write)
	if write != "" {
		writesAll := true
		for _, r := range readable {
			writesAll = writesAll && writable[r]
		}
		if writesAll {
			gh = write
		}
	}
	host := g.GitHost
	https := "https://" + host + "/"
	config := [][2]string{
		// An empty helper sets aside every helper configured before it.
		{"credential.helper", ""},
		{"credential.https://" + host + ".helper", gitHelper(self)},
		{"credential.https://" + host + ".useHttpPath", "true"},
		// SSH addresses on GitHub, for fetching and for pushing, go over
		// HTTPS instead, with what was lent.
		{"url." + https + ".insteadOf", "git@" + host + ":"},
		{"url." + https + ".insteadOf", "ssh://git@" + host + "/"},
		{"url." + https + ".pushInsteadOf", "git@" + host + ":"},
		{"url." + https + ".pushInsteadOf", "ssh://git@" + host + "/"},
	}
	env = append(env, "GH_TOKEN="+gh, envGitHubHost+"="+host, "GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_COUNT="+strconv.Itoa(len(config)))
	for i, kv := range config {
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, kv[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, kv[1]))
	}
	if g.AuthorName != "" {
		env = append(env, "GIT_AUTHOR_NAME="+g.AuthorName, "GIT_COMMITTER_NAME="+g.AuthorName)
	}
	if g.AuthorEmail != "" {
		env = append(env, "GIT_AUTHOR_EMAIL="+g.AuthorEmail, "GIT_COMMITTER_EMAIL="+g.AuthorEmail)
	}
	return env
}

// gitHelper is git's credential.helper value that runs this program. git runs
// a value starting with ! through its shell, which on Windows is the one Git
// for Windows brings, so the path is quoted and written with forward slashes.
func gitHelper(self string) string {
	p := filepath.ToSlash(self)
	return "!'" + strings.ReplaceAll(p, "'", `'\''`) + "' github-credential"
}

// ServeGitHubCredential is `agent-host github-credential <operation>`, which
// git runs as its credential helper during a run lent GitHub access. For
// "get" it reads what git asks for on in and answers on out with the token for
// that repository from the environment: the write token for a repository the
// AI agent may write, the read token for one it may only read, and nothing
// for any other — so git asks no one else and fails. Every other operation
// (store, erase) is ignored: there is nothing on this machine to keep.
func ServeGitHubCredential(args []string, in io.Reader, out io.Writer, getenv func(string) string) int {
	if len(args) == 0 || args[len(args)-1] != "get" {
		return 0
	}
	ask := map[string]string{}
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			ask[k] = v
		}
	}
	host := getenv(envGitHubHost)
	if ask["protocol"] != "https" || host == "" || !strings.EqualFold(ask["host"], host) {
		return 0
	}
	repo := strings.ToLower(strings.TrimSuffix(strings.Trim(ask["path"], "/"), ".git"))
	token := ""
	switch {
	case repo != "" && listed(getenv(envGitHubWriteRepos), repo):
		token = getenv(envGitHubWriteToken)
	case repo != "" && listed(getenv(envGitHubReadRepos), repo):
		token = getenv(envGitHubReadToken)
	}
	if token == "" {
		return 0
	}
	fmt.Fprintf(out, "username=x-access-token\npassword=%s\n", token)
	return 0
}

func listed(list, repo string) bool {
	for _, x := range strings.Split(list, ",") {
		if strings.TrimSpace(x) == repo {
			return true
		}
	}
	return false
}

// lendGitHubForTurn borrows GitHub access for one turn, as the brain's
// environment. Nil with no error when the AI agent is lent none. A failure to
// borrow is said and the turn runs without it: the brain is told by git and gh
// that it cannot reach a repository, which is the truth.
func (h *Host) lendGitHubForTurn(ctx context.Context, logf func(string, ...any)) ([]string, *LentGitHub) {
	g, err := h.BorrowGitHub(ctx)
	if errors.Is(err, ErrNoGitHub) {
		return nil, nil
	}
	if err != nil {
		logf("[agent-host] %v; the brain runs without GitHub access", err)
		return nil, nil
	}
	self, err := executable()
	if err != nil {
		logf("[agent-host] this program cannot be found to serve git its token (%v); the brain runs without GitHub access", err)
		h.giveGitHubBack(g, logf)
		return nil, nil
	}
	return g.Env(self), g
}
