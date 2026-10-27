package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/githubapp"
	"identity-agent-core/sandbox"

	"github.com/go-chi/chi/v5"
)

// An AI agent may be granted GitHub repositories, read or write, as a
// capability grant (code.repository.read, code.repository.write), each
// limited to the repositories it names.
//
// The organisation connects its GitHub App once. The App's private key, App
// ID and installation are kept in this Identity Agent's vault and never
// returned. When an AI agent's body starts a run it asks, sealed and signed by
// its machine key, for GitHub access; this Identity Agent runs the one check,
// asks GitHub for an installation token limited to exactly the repositories and
// access the grant gives, lends it sealed to that body for the run, and records
// the lend. When the run ends the body returns it, and the token is withdrawn
// at GitHub. Revoking the AI agent, its grant for a repository, or its body
// withdraws every token lent that it no longer covers, at once.
//
// No person rotates anything: every run gets a token GitHub made for it, that
// lapses within the hour on its own. The one long-lived secret, the App's key,
// is used only to ask GitHub for those.

// The capabilities that grant repositories.
const (
	capabilityRepoRead  = "code.repository.read"
	capabilityRepoWrite = "code.repository.write"
	// repoArgument is the argument their grants limit.
	repoArgument = "repository"
)

func capabilityFor(a githubapp.Access) string {
	if a == githubapp.Write {
		return capabilityRepoWrite
	}
	return capabilityRepoRead
}

var (
	githubAppRef   = sandbox.KeptRef("github-app")
	githubLendsRef = sandbox.KeptRef("github-lends")
)

const (
	keptGitHubApp   = "github-app"
	keptGitHubLends = "github-lends"
)

func (s *CoreServer) mountGitHubRoutes(r chi.Router) {
	// The owner's front end — the owner or a controller they authorised.
	r.Get("/github", s.handleGetGitHub)
	r.Put("/github", s.handleConnectGitHub)
	r.Delete("/github", s.handleDisconnectGitHub)
	r.Get("/github/repositories", s.handleGitHubRepositories)
	r.Get("/mcp/agents/{id}/github", s.handleGetAgentGitHub)
	r.Put("/mcp/agents/{id}/github", s.handleSetAgentGitHub)
	// The body's side: signed by its machine key, and taken only sealed.
	r.Post("/agent-host/github", s.handleBodyBorrowsGitHub)
	r.Post("/agent-host/github/return", s.handleBodyReturnsGitHub)
}

// githubClient is how this Identity Agent talks to GitHub: through its
// governed way out, with the same policy check — including any domain the
// owner blocked — proxy log and trace as its own calls, adding no key of the
// vault's, and following no redirect. GitHub's address is not something a
// request can set (githubAPI exists for tests only).
func (s *CoreServer) githubClient() (githubapp.Client, error) {
	if s.SandboxManager == nil {
		return githubapp.Client{}, errNoVault
	}
	return githubapp.Client{API: s.githubAPI, Send: func(ctx context.Context, req *http.Request, client *http.Client) (*http.Response, error) {
		return s.SandboxManager.MakeTrackedRequestAsGiven(ctx, req, client)
	}}, nil
}

// githubConnection is the organisation's GitHub App, key and all, if one is
// connected.
func (s *CoreServer) githubConnection() (githubapp.Connection, bool, error) {
	var c githubapp.Connection
	vault, err := s.brainVault()
	if err != nil {
		return c, false, err
	}
	had, err := vault.Kept(githubAppRef, keptGitHubApp, &c)
	return c, had, err
}

// githubConnectionView is the connection as it may be shown: never its key.
func githubConnectionView(c githubapp.Connection, had bool) map[string]any {
	if !had {
		return map[string]any{"connected": false}
	}
	return map[string]any{
		"connected": true, "app_id": c.AppID, "installation_id": c.InstallationID,
		"app_slug": c.AppSlug, "app_name": c.AppName, "account": c.Account,
		"key_fingerprint": c.KeyFingerprint(), "connected_at": c.ConnectedAt,
		"commits_as": c.BotName(), "git_host": githubapp.DefaultGitHost,
	}
}

// recordGitHubEvent writes what happened to the organisation's GitHub
// connection into the signed record, as whoever did it. Never the key.
func (s *CoreServer) recordGitHubEvent(r *http.Request, event, status, why string) {
	by := firstNonEmptyString(madeByController(r), "the owner")
	log.Printf("[github] %s by %s: %s (%s)", event, by, why, status)
	if s.SandboxManager == nil {
		return
	}
	cc := sandbox.CallerContext{CallerAID: firstNonEmptyString(madeByController(r), s.OwnerRootAID()), Reason: why}
	s.SandboxManager.RecordGovernanceEvent(cc, "github."+event, status)
}

// ── Connecting the organisation's GitHub App ─────────────────────────────────

func (s *CoreServer) handleGetGitHub(w http.ResponseWriter, _ *http.Request) {
	c, had, err := s.githubConnection()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSONStatus(w, http.StatusOK, githubConnectionView(c, had))
}

// githubConnectRequest is a GitHub App as a screen sends it. PrivateKey is
// the .pem file GitHub gave; it is never returned.
type githubConnectRequest struct {
	AppID          int64  `json:"app_id"`
	InstallationID int64  `json:"installation_id"`
	PrivateKey     string `json:"private_key"`
}

// handleConnectGitHub connects the organisation's GitHub App, or replaces the
// one connected. GitHub is asked first, with the key, what the App and its
// installation are, so a wrong key or number is reported now and nothing is
// kept. Tokens lent under an App it replaces are withdrawn.
func (s *CoreServer) handleConnectGitHub(w http.ResponseWriter, r *http.Request) {
	var q githubConnectRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&q); err != nil {
		jsonError(w, "the GitHub App is unreadable", http.StatusBadRequest)
		return
	}
	if _, err := githubapp.ParsePrivateKey(q.PrivateKey); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	vault, err := s.brainVaultWritable()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	gh, err := s.githubClient()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	conn, err := gh.Describe(ctx, githubapp.Connection{AppID: q.AppID, InstallationID: q.InstallationID,
		PrivateKey: strings.TrimSpace(q.PrivateKey) + "\n"})
	if err != nil {
		s.recordGitHubEvent(r, "connect", "failed", err.Error())
		jsonError(w, "the GitHub App was not connected: "+err.Error(), http.StatusBadRequest)
		return
	}
	conn.ConnectedAt = time.Now().UTC()
	prev, had, _ := s.githubConnection()
	if had && (prev.AppID != conn.AppID || prev.InstallationID != conn.InstallationID) {
		s.withdrawAllLentGitHubAccess("the organisation connected another GitHub App")
	}
	if err := vault.SetKept(githubAppRef, keptGitHubApp, conn); err != nil {
		jsonError(w, "the GitHub App was not kept: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	s.recordGitHubEvent(r, "connected", "ok", fmt.Sprintf("GitHub App %d (%s), installation %d on %s",
		conn.AppID, conn.AppSlug, conn.InstallationID, conn.Account))
	writeJSONStatus(w, http.StatusOK, githubConnectionView(conn, true))
}

// handleDisconnectGitHub withdraws every token lent, then forgets the App.
// The AI agents' grants still name their repositories, and lend nothing until
// an App is connected again.
func (s *CoreServer) handleDisconnectGitHub(w http.ResponseWriter, r *http.Request) {
	vault, err := s.brainVaultWritable()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	left := s.withdrawAllLentGitHubAccess("the organisation disconnected its GitHub App")
	if err := vault.RemoveKept(githubAppRef); err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	why := "disconnected"
	if left > 0 {
		why += fmt.Sprintf("; %d token(s) lent could not be withdrawn at GitHub and lapse on their own within the hour", left)
	}
	s.recordGitHubEvent(r, "disconnected", "ok", why)
	writeJSONStatus(w, http.StatusOK, map[string]any{"connected": false, "not_withdrawn": left})
}

// handleGitHubRepositories lists the repositories the App can reach, so a
// screen offers only those. Nothing secret is returned.
func (s *CoreServer) handleGitHubRepositories(w http.ResponseWriter, r *http.Request) {
	conn, had, err := s.githubConnection()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !had {
		jsonError(w, "no GitHub App is connected", http.StatusNotFound)
		return
	}
	gh, err := s.githubClient()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	repos, err := gh.Repositories(ctx, conn)
	if err != nil {
		jsonError(w, "GitHub's list of repositories could not be read: "+err.Error(), http.StatusBadGateway)
		return
	}
	if repos == nil {
		repos = []githubapp.Repository{}
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"account": conn.Account, "repositories": repos})
}

// ── Which repositories an AI agent may use ───────────────────────────────────

// repoGrant is one repository an AI agent may use, and how.
type repoGrant struct {
	Repository string           `json:"repository"`
	Access     githubapp.Access `json:"access"`
}

// reposIn is what a grant gives, as repository → access: the repositories
// each capability's grant names, write where both do. A capability granted
// with no repositories gives none.
func reposIn(scopes []string, constraints map[string]interface{}) map[string]githubapp.Access {
	out := map[string]githubapp.Access{}
	for _, access := range []githubapp.Access{githubapp.Read, githubapp.Write} {
		capID := capabilityFor(access)
		if !containsString(scopes, capID) {
			continue
		}
		args, _ := constraints[capID].(map[string]interface{})
		list, _ := args[repoArgument].([]interface{})
		for _, v := range list {
			name, ok := v.(string)
			if !ok {
				continue
			}
			repo, err := githubapp.NormaliseRepository(name)
			if err != nil {
				continue
			}
			if access == githubapp.Write || out[repo] == "" {
				out[repo] = access
			}
		}
	}
	return out
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func sortedGrants(m map[string]githubapp.Access) []repoGrant {
	out := make([]repoGrant, 0, len(m))
	for repo, access := range m {
		out = append(out, repoGrant{Repository: repo, Access: access})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repository < out[j].Repository })
	return out
}

func (s *CoreServer) handleGetAgentGitHub(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	conn, had, err := s.githubConnection()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	lent := []map[string]any{}
	for _, l := range s.githubLends() {
		if l.Agent != a.ID || l.Returned {
			continue
		}
		lent = append(lent, map[string]any{"lend_id": l.ID, "host": l.Host, "lent_at": l.LentAt,
			"expires_at": l.expires(), "repositories": l.grants()})
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"connected": had, "account": conn.Account,
		"repositories": sortedGrants(reposIn(a.Capabilities, a.GrantConstraints)), "lent": lent,
	})
}

// handleSetAgentGitHub replaces the repositories an AI agent may use, by
// re-issuing its grant: its other capabilities and limits are kept as they
// are. Only repositories the organisation's GitHub App can reach are taken.
func (s *CoreServer) handleSetAgentGitHub(w http.ResponseWriter, r *http.Request) {
	if s.assetHandler == nil {
		jsonError(w, "asset handler not initialized", http.StatusServiceUnavailable)
		return
	}
	// Who asked, read before the body is: the request is kept as it was signed.
	by, release, err := s.authorityOf(r)
	if err != nil {
		jsonError(w, "who asked for this change: "+err.Error(), http.StatusForbidden)
		return
	}
	defer release()
	id := chi.URLParam(r, "id")
	by.About = id
	if _, ok := s.aiAgentAsset(id); !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	var q struct {
		Repositories []struct {
			Repository string `json:"repository"`
			Access     string `json:"access"`
		} `json:"repositories"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&q); err != nil || q.Repositories == nil {
		jsonError(w, "name the repositories it may use (send [] for none)", http.StatusBadRequest)
		return
	}
	want := map[string]githubapp.Access{}
	for _, x := range q.Repositories {
		repo, err := githubapp.NormaliseRepository(x.Repository)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		access, err := githubapp.ParseAccess(x.Access)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if access == githubapp.Write || want[repo] == "" {
			want[repo] = access
		}
	}
	if len(want) > 0 {
		conn, had, err := s.githubConnection()
		if err != nil {
			jsonError(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		if !had {
			jsonError(w, "connect the organisation's GitHub App first", http.StatusConflict)
			return
		}
		gh, err := s.githubClient()
		if err != nil {
			jsonError(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		reachable, err := gh.Repositories(ctx, conn)
		cancel()
		if err != nil {
			jsonError(w, "GitHub's list of repositories could not be read, so nothing was changed: "+err.Error(), http.StatusBadGateway)
			return
		}
		can := map[string]bool{}
		for _, x := range reachable {
			can[x.FullName] = true
		}
		for repo := range want {
			if !can[repo] {
				jsonError(w, repo+" is not one the organisation's GitHub App can reach; install the App on it at GitHub first",
					http.StatusBadRequest)
				return
			}
		}
	}
	res, status, err := s.regrantAgent(id, by, func(c *asset.Asset) error {
		caps := make([]string, 0, len(c.Capabilities)+2)
		for _, x := range c.Capabilities {
			if x != capabilityRepoRead && x != capabilityRepoWrite {
				caps = append(caps, x)
			}
		}
		limits := map[string]interface{}{}
		for k, v := range c.GrantConstraints {
			if k != capabilityRepoRead && k != capabilityRepoWrite {
				limits[k] = v
			}
		}
		for _, access := range []githubapp.Access{githubapp.Read, githubapp.Write} {
			var repos []interface{}
			for _, g := range sortedGrants(want) {
				if g.Access == access {
					repos = append(repos, g.Repository)
				}
			}
			if len(repos) > 0 {
				caps = append(caps, capabilityFor(access))
				limits[capabilityFor(access)] = map[string]interface{}{repoArgument: repos}
			}
		}
		c.Capabilities = asset.NormaliseCapabilities(caps)
		c.GrantConstraints = limits
		return nil
	})
	if err != nil {
		jsonError(w, err.Error(), status)
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"asset_id": res.updated.ID, "grant_said": res.grantSAID, "grant_issued": res.grantSAID != "",
		"repositories": sortedGrants(reposIn(res.updated.Capabilities, res.updated.GrantConstraints)),
	})
}

// ── What was lent, and withdrawing it ────────────────────────────────────────

// githubLend is one run's GitHub access: the tokens lent to a body, kept in
// the vault until each is withdrawn at GitHub or has lapsed there, so this
// Identity Agent can withdraw them early.
type githubLend struct {
	ID       string            `json:"id"`
	Agent    string            `json:"agent"`
	AgentAID string            `json:"agent_aid"`
	Host     string            `json:"host"`
	LentAt   time.Time         `json:"lent_at"`
	Tokens   []githubapp.Token `json:"tokens"`
	// Returned is a lend given back, or withdrawn, whose tokens GitHub could
	// not be reached to withdraw yet. It is tried again until they lapse.
	Returned bool `json:"returned,omitempty"`
}

func (l githubLend) expires() time.Time {
	var t time.Time
	for _, x := range l.Tokens {
		if x.ExpiresAt.After(t) {
			t = x.ExpiresAt
		}
	}
	return t
}

func (l githubLend) grants() []repoGrant {
	m := map[string]githubapp.Access{}
	for _, t := range l.Tokens {
		for _, r := range t.Repositories {
			m[r] = t.Access
		}
	}
	return sortedGrants(m)
}

// githubLendsMu keeps one change to what was lent at a time.
var githubLendsMu sync.Mutex

func (s *CoreServer) githubLends() []githubLend {
	githubLendsMu.Lock()
	defer githubLendsMu.Unlock()
	all, _ := s.loadGitHubLendsLocked()
	return all
}

func (s *CoreServer) loadGitHubLendsLocked() ([]githubLend, error) {
	vault, err := s.brainVault()
	if err != nil {
		return nil, err
	}
	var all []githubLend
	_, err = vault.Kept(githubLendsRef, keptGitHubLends, &all)
	return all, err
}

func (s *CoreServer) saveGitHubLendsLocked(all []githubLend) error {
	vault, err := s.brainVault()
	if err != nil {
		return err
	}
	if len(all) == 0 {
		return vault.RemoveKept(githubLendsRef)
	}
	return vault.SetKept(githubLendsRef, keptGitHubLends, all)
}

// stillGranted says why a lend is no longer covered — its AI agent gone,
// revoked or lapsed, its body no longer the AI agent's, its grant no longer
// giving a repository the way it was lent, or the one check refusing — or ""
// when every token it holds is still given.
func (s *CoreServer) stillGranted(l githubLend, conn githubapp.Connection, connected bool) string {
	if !connected {
		return "the organisation's GitHub App is no longer connected"
	}
	a, ok := s.aiAgentAsset(l.Agent)
	if !ok {
		return "the AI agent is gone"
	}
	if b, ok := s.bodies().ActiveByHost(l.Host); !ok || b.AgentAssetID != a.ID {
		return "the machine is no longer this AI agent's body"
	}
	cc, ok := s.ResolveAgentCaller(a.PairwiseAID)
	if !ok {
		return "the AI agent is gone"
	}
	if err := s.mayBeLent(a, cc, "GitHub access"); err != nil {
		return err.Error()
	}
	granted := s.lendableRepos(cc)
	for _, t := range l.Tokens {
		for _, repo := range t.Repositories {
			got := granted[repo]
			if got == "" || (t.Access == githubapp.Write && got != githubapp.Write) {
				return fmt.Sprintf("its grant no longer gives %s %s access", repo, t.Access)
			}
		}
	}
	return ""
}

// lendableRepos is what may be lent to cc: the repositories its grant gives,
// for each capability that passes the one check.
func (s *CoreServer) lendableRepos(cc sandbox.CallerContext) map[string]githubapp.Access {
	out := reposIn(cc.Scopes, cc.ResourceConstraints)
	for _, access := range []githubapp.Access{githubapp.Write, githubapp.Read} {
		if ok, _ := s.SandboxManager.MayBeLent(cc, capabilityFor(access)); ok {
			continue
		}
		for repo, a := range out {
			if a == access {
				delete(out, repo)
			}
		}
	}
	return out
}

// revokeLend withdraws every token of a lend at GitHub, and reports whether
// all of them are withdrawn or lapsed.
func (s *CoreServer) revokeLend(ctx context.Context, l githubLend) bool {
	gh, err := s.githubClient()
	if err != nil {
		return false
	}
	now := time.Now()
	all := true
	for _, t := range l.Tokens {
		if !now.Before(t.ExpiresAt) {
			continue
		}
		if err := gh.Revoke(ctx, t.Token); err != nil {
			log.Printf("[github] lend %s: a token could not be withdrawn at GitHub yet: %v", l.ID, err)
			all = false
		}
	}
	return all
}

// recordGitHubLendEvent writes what happened to an AI agent's GitHub access
// into the signed record, as the AI agent, naming the body. Never a token.
func (s *CoreServer) recordGitHubLendEvent(a asset.Asset, cc sandbox.CallerContext, event, status, why string) {
	cc.Transport = firstNonEmptyString(cc.Transport, "body")
	s.recordLentEvent(a, cc, "agent.github."+event, status, why)
}

// withdrawLentGitHubAccessNoLongerGranted withdraws, at GitHub, every token
// lent that its AI agent's grant no longer covers, and lets go of every lend
// whose tokens have lapsed. It is run whenever a grant or a body changes, and
// every minute, so a token outlives what it was lent for only while GitHub
// cannot be reached.
func (s *CoreServer) withdrawLentGitHubAccessNoLongerGranted(why string) {
	if s.SandboxManager == nil || s.assetHandler == nil {
		return
	}
	githubLendsMu.Lock()
	defer githubLendsMu.Unlock()
	all, err := s.loadGitHubLendsLocked()
	if err != nil || len(all) == 0 {
		return
	}
	conn, connected, err := s.githubConnection()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now()
	kept := all[:0]
	changed := false
	for _, l := range all {
		if !now.Before(l.expires()) {
			changed = true
			continue
		}
		reason := ""
		if !l.Returned {
			reason = s.stillGranted(l, conn, connected)
			if reason == "" {
				kept = append(kept, l)
				continue
			}
		}
		changed = true
		done := s.revokeLend(ctx, l)
		if reason != "" {
			if a, ok := s.aiAgentAsset(l.Agent); ok {
				status := "ok"
				if !done {
					status = "error"
				}
				s.recordGitHubLendEvent(a, sandbox.CallerContext{BodyHost: l.Host}, "withdrawn", status,
					fmt.Sprintf("lend %s withdrawn because %s (%s)", l.ID, reason, why))
			}
		}
		if !done {
			l.Returned = true
			kept = append(kept, l)
		}
	}
	if changed {
		if err := s.saveGitHubLendsLocked(kept); err != nil {
			log.Printf("[github] what is still lent could not be saved: %v", err)
		}
	}
}

// withdrawAllLentGitHubAccess withdraws every token lent, and says how many
// could not be withdrawn at GitHub yet.
func (s *CoreServer) withdrawAllLentGitHubAccess(why string) int {
	githubLendsMu.Lock()
	defer githubLendsMu.Unlock()
	all, err := s.loadGitHubLendsLocked()
	if err != nil || len(all) == 0 {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	left := 0
	var kept []githubLend
	for _, l := range all {
		if !time.Now().Before(l.expires()) {
			continue
		}
		done := s.revokeLend(ctx, l)
		if a, ok := s.aiAgentAsset(l.Agent); ok && !l.Returned {
			s.recordGitHubLendEvent(a, sandbox.CallerContext{BodyHost: l.Host}, "withdrawn", map[bool]string{true: "ok", false: "error"}[done],
				fmt.Sprintf("lend %s withdrawn because %s", l.ID, why))
		}
		if !done {
			left++
			l.Returned = true
			kept = append(kept, l)
		}
	}
	if err := s.saveGitHubLendsLocked(kept); err != nil {
		log.Printf("[github] what is still lent could not be saved: %v", err)
	}
	return left
}

// keepWithdrawingLentGitHubAccess checks what is lent every minute: a grant
// that lapses by time changes nothing anybody does, and a token GitHub could
// not be reached to withdraw is tried again.
func (s *CoreServer) keepWithdrawingLentGitHubAccess(stop <-chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.withdrawLentGitHubAccessNoLongerGranted("checked every minute")
		}
	}
}

// ── The body's side ──────────────────────────────────────────────────────────

// handleBodyBorrowsGitHub lends a body GitHub access for one run: a token for
// the repositories its AI agent's grant gives write access to, and one for
// those it may read, each limited to exactly those. A body may name fewer.
func (s *CoreServer) handleBodyBorrowsGitHub(w http.ResponseWriter, r *http.Request) {
	cc, b, a, ok := s.theBodyAndItsAgent(w, r)
	if !ok {
		return
	}
	var q struct {
		Repositories []string `json:"repositories,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&q); err != nil && !errors.Is(err, io.EOF) {
		jsonError(w, "the request is unreadable", http.StatusBadRequest)
		return
	}
	s.withdrawLentGitHubAccessNoLongerGranted("a body asked for GitHub access")
	if err := s.mayBeLent(a, cc, "GitHub access"); err != nil {
		s.recordGitHubLendEvent(a, cc, "lend", "denied", err.Error())
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}
	granted := reposIn(cc.Scopes, cc.ResourceConstraints)
	if len(granted) == 0 {
		// Not a refusal: this AI agent uses no repositories.
		writeJSONStatus(w, http.StatusNotFound, map[string]any{
			"error": "this AI agent's grant gives it no GitHub repositories", "no_github": true})
		return
	}
	conn, had, err := s.githubConnection()
	if err != nil {
		jsonError(w, "the organisation's GitHub App cannot be read: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !had {
		s.recordGitHubLendEvent(a, cc, "lend", "denied", "no GitHub App is connected")
		writeJSONStatus(w, http.StatusNotFound, map[string]any{
			"error": "the organisation has not connected its GitHub App", "no_github": true})
		return
	}
	// The one check, for each capability lent.
	lendable := s.lendableRepos(cc)
	if len(q.Repositories) > 0 {
		narrowed := map[string]githubapp.Access{}
		for _, name := range q.Repositories {
			repo, err := githubapp.NormaliseRepository(name)
			if err != nil {
				jsonError(w, err.Error(), http.StatusBadRequest)
				return
			}
			if lendable[repo] == "" {
				why := "this AI agent's grant does not give it " + repo
				s.recordGitHubLendEvent(a, cc, "lend", "denied", why)
				jsonError(w, why, http.StatusForbidden)
				return
			}
			narrowed[repo] = lendable[repo]
		}
		lendable = narrowed
	}
	if len(lendable) == 0 {
		why := "the one check refused every repository this AI agent's grant names"
		for _, access := range []githubapp.Access{githubapp.Write, githubapp.Read} {
			if ok, reason := s.SandboxManager.MayBeLent(cc, capabilityFor(access)); !ok && reason != "" {
				why = reason
			}
		}
		s.recordGitHubLendEvent(a, cc, "lend", "denied", why)
		jsonError(w, why, http.StatusForbidden)
		return
	}
	gh, err := s.githubClient()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	lend := githubLend{ID: newGitHubLendID(), Agent: a.ID, AgentAID: a.PairwiseAID, Host: b.Host, LentAt: time.Now().UTC()}
	for _, access := range []githubapp.Access{githubapp.Write, githubapp.Read} {
		var repos []string
		for _, g := range sortedGrants(lendable) {
			if g.Access == access {
				repos = append(repos, g.Repository)
			}
		}
		if len(repos) == 0 {
			continue
		}
		tok, err := gh.Mint(ctx, conn, repos, access)
		if err != nil {
			s.revokeLend(context.WithoutCancel(ctx), lend)
			s.recordGitHubLendEvent(a, cc, "lend", "error", "GitHub made no token: "+err.Error())
			jsonError(w, "GitHub made no token for this run: "+err.Error(), http.StatusBadGateway)
			return
		}
		lend.Tokens = append(lend.Tokens, tok)
	}
	githubLendsMu.Lock()
	all, err := s.loadGitHubLendsLocked()
	if err == nil {
		err = s.saveGitHubLendsLocked(append(all, lend))
	}
	githubLendsMu.Unlock()
	if err != nil {
		// A token this Identity Agent could not withdraw later is not lent.
		s.revokeLend(context.WithoutCancel(ctx), lend)
		jsonError(w, "the lend could not be recorded, so nothing was lent: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	var parts []string
	tokens := make([]map[string]any, 0, len(lend.Tokens))
	for _, t := range lend.Tokens {
		parts = append(parts, fmt.Sprintf("%s %s", strings.Join(t.Repositories, ", "), t.Access))
		tokens = append(tokens, map[string]any{"access": t.Access, "repositories": t.Repositories,
			"token": t.Token, "expires_at": t.ExpiresAt})
	}
	s.recordGitHubLendEvent(a, cc, "lent", "ok", fmt.Sprintf("lend %s: %s, until %s",
		lend.ID, strings.Join(parts, "; "), lend.expires().Format(time.RFC3339)))
	name := firstNonEmptyString(a.DisplayName, "AI agent")
	// This answer travels sealed to the keys the body enrolled with: the
	// route is reached only through the sealed transport (theBodyAsking).
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"lend_id": lend.ID, "expires_at": lend.expires(), "git_host": githubapp.DefaultGitHost,
		"author_name": name, "author_email": conn.BotEmail(), "commits_as": conn.BotName(),
		"tokens": tokens,
	})
}

// handleBodyReturnsGitHub takes a run's GitHub access back, and withdraws its
// tokens at GitHub. One GitHub cannot be reached for is tried again, every
// minute, until it lapses.
func (s *CoreServer) handleBodyReturnsGitHub(w http.ResponseWriter, r *http.Request) {
	cc, b, a, ok := s.theBodyAndItsAgent(w, r)
	if !ok {
		return
	}
	var q struct {
		LendID string `json:"lend_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&q); err != nil || q.LendID == "" {
		jsonError(w, "name the lend to return", http.StatusBadRequest)
		return
	}
	githubLendsMu.Lock()
	defer githubLendsMu.Unlock()
	all, err := s.loadGitHubLendsLocked()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	for i, l := range all {
		if l.ID != q.LendID || l.Host != b.Host || l.Agent != a.ID {
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		done := s.revokeLend(ctx, l)
		cancel()
		rest := append(append([]githubLend{}, all[:i]...), all[i+1:]...)
		if !done {
			l.Returned = true
			rest = append(rest, l)
		}
		if err := s.saveGitHubLendsLocked(rest); err != nil {
			log.Printf("[github] lend %s: its return could not be saved: %v", l.ID, err)
		}
		why := "lend " + l.ID + " returned and its tokens withdrawn at GitHub"
		status := "ok"
		if !done {
			why = "lend " + l.ID + " returned; GitHub could not be reached to withdraw its tokens yet, so it is tried again until they lapse"
			status = "error"
		}
		s.recordGitHubLendEvent(a, cc, "returned", status, why)
		writeJSONStatus(w, http.StatusOK, map[string]any{"returned": true, "withdrawn": done})
		return
	}
	writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": "this body holds no such lend", "no_lend": true})
}

func newGitHubLendID() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "gl_" + base64.RawURLEncoding.EncodeToString(b)
}
