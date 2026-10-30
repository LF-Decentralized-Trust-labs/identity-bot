package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/githubapp"
	"identity-agent-core/githubrepo"
	"identity-agent-core/lending"
	"identity-agent-core/permission"
	"identity-agent-core/vault"

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

// The capabilities that grant repositories, and the arguments their grants
// limit, as githubapp defines them.
const (
	capabilityRepoRead  = githubrepo.CapabilityRead
	capabilityRepoWrite = githubrepo.CapabilityWrite
	repoArgument        = githubrepo.RepositoryArgument
	repoIDArgument      = githubrepo.RepositoryIDArgument
)

func capabilityFor(a githubrepo.Access) string { return a.Capability() }

var githubAppRef = vault.KeptRef("github-app")

const keptGitHubApp = "github-app"

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
	theVault, err := s.brainVault()
	if err != nil {
		return c, false, err
	}
	had, err := theVault.Kept(githubAppRef, keptGitHubApp, &c)
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
	if s.ActivityLog == nil {
		return
	}
	cc := permission.CallerContext{CallerAID: firstNonEmptyString(madeByController(r), s.OwnerRootAID()), Reason: why}
	s.ActivityLog.RecordGovernanceEvent(cc, "github."+event, status)
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
	theVault, err := s.brainVaultWritable()
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
	_, had, _ := s.githubConnection()
	if err := theVault.SetKept(githubAppRef, keptGitHubApp, conn); err != nil {
		jsonError(w, "the GitHub App was not kept: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	// Replacing the App — another App, another installation, or only its key —
	// withdraws everything lent under the one it replaces. A lend recorded
	// meanwhile names the App that made it, and the check after recording
	// withdraws it too.
	if had {
		s.endAllGitHubLends(context.WithoutCancel(ctx), "the organisation replaced its GitHub App")
	}
	s.recordGitHubEvent(r, "connected", "ok", fmt.Sprintf("GitHub App %d (%s), installation %d on %s",
		conn.AppID, conn.AppSlug, conn.InstallationID, conn.Account))
	writeJSONStatus(w, http.StatusOK, githubConnectionView(conn, true))
}

// endAllGitHubLends ends every GitHub lend and withdraws its tokens, and says
// how many lends still hold a token GitHub could not be reached to withdraw.
func (s *CoreServer) endAllGitHubLends(ctx context.Context, why string) (int, error) {
	ended, left, err := s.lends().EndAll(ctx, lendGitHub, why, time.Now().UTC())
	s.recordEnded(ended, "")
	return left, err
}

// handleDisconnectGitHub withdraws every token lent, then forgets the App.
// The AI agents' grants still name their repositories, and lend nothing until
// an App is connected again.
func (s *CoreServer) handleDisconnectGitHub(w http.ResponseWriter, r *http.Request) {
	theVault, err := s.brainVaultWritable()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	left, err := s.endAllGitHubLends(ctx, "the organisation disconnected its GitHub App")
	if err != nil {
		jsonError(w, "what was lent cannot be read, so the App was not disconnected: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	if err := theVault.RemoveKept(githubAppRef); err != nil {
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

// repoGrant is one repository an AI agent may use, and how. ID is GitHub's
// number for the repository: a grant gives that repository, so one deleted and
// made again under the same name is not given.
type repoGrant struct {
	Repository string            `json:"repository"`
	ID         int64             `json:"id"`
	Access     githubrepo.Access `json:"access"`
}

// stringsIn reads a constraint's list of values.
func stringsIn(v interface{}) []string {
	switch l := v.(type) {
	case []string:
		return l
	case []interface{}:
		out := make([]string, 0, len(l))
		for _, x := range l {
			s, _ := x.(string)
			out = append(out, s)
		}
		return out
	}
	return nil
}

// namedIn are the repositories one capability's grant names, by GitHub's
// number: the grant names each as owner/name in "repository" and by number,
// in the same place, in "repository_id". One named without its number gives
// nothing.
func namedIn(constraints map[string]interface{}, capID string) map[int64]string {
	args, _ := constraints[capID].(map[string]interface{})
	names, ids := stringsIn(args[repoArgument]), stringsIn(args[repoIDArgument])
	out := map[int64]string{}
	for i, name := range names {
		repo, err := githubrepo.NormaliseRepository(name)
		if err != nil || i >= len(ids) {
			continue
		}
		id, err := strconv.ParseInt(ids[i], 10, 64)
		if err != nil || id <= 0 {
			continue
		}
		out[id] = repo
	}
	return out
}

// reposIn is what a grant gives, by repository: write where the write
// capability's grant names it, otherwise read. A capability granted with no
// repositories gives none.
func reposIn(scopes []string, constraints map[string]interface{}) map[int64]repoGrant {
	out := map[int64]repoGrant{}
	for _, access := range []githubrepo.Access{githubrepo.Read, githubrepo.Write} {
		capID := capabilityFor(access)
		if !containsString(scopes, capID) {
			continue
		}
		for id, name := range namedIn(constraints, capID) {
			out[id] = repoGrant{Repository: name, ID: id, Access: access}
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

func sortedGrants(m map[int64]repoGrant) []repoGrant {
	out := make([]repoGrant, 0, len(m))
	for _, g := range m {
		out = append(out, g)
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
	open, _ := s.lends().Open(lendGitHub, time.Now().UTC())
	for _, l := range open {
		if l.Agent != a.ID {
			continue
		}
		d, _ := githubLendDataOf(l)
		lent = append(lent, map[string]any{"lend_id": l.ID, "host": l.Host, "lent_at": l.LentAt,
			"expires_at": d.expires(), "repositories": d.grants()})
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"connected": had, "account": conn.Account,
		"repositories": sortedGrants(reposIn(a.Capabilities, a.GrantConstraints)), "lent": lent,
	})
}

// handleSetAgentGitHub replaces the repositories an AI agent may use, by
// re-issuing its grant: its other capabilities and limits are kept as they
// are. Only repositories the organisation's GitHub App can reach are taken,
// and each is kept by GitHub's number for it as well as its name.
//
// A repository it may write is named under read as well: write includes read,
// so a run refused write access — its score too low for a change, say — can
// still read it.
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
	want := map[string]githubrepo.Access{}
	for _, x := range q.Repositories {
		repo, err := githubrepo.NormaliseRepository(x.Repository)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		access, err := githubrepo.ParseAccess(x.Access)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if access == githubrepo.Write || want[repo] == "" {
			want[repo] = access
		}
	}
	grants := map[int64]repoGrant{}
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
		number := map[string]int64{}
		for _, x := range reachable {
			number[x.FullName] = x.ID
		}
		for repo, access := range want {
			n := number[repo]
			if n <= 0 {
				jsonError(w, repo+" is not one the organisation's GitHub App can reach; install the App on it at GitHub first",
					http.StatusBadRequest)
				return
			}
			grants[n] = repoGrant{Repository: repo, ID: n, Access: access}
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
		for _, access := range []githubrepo.Access{githubrepo.Read, githubrepo.Write} {
			var names, ids []interface{}
			for _, g := range sortedGrants(grants) {
				if access == githubrepo.Read || g.Access == githubrepo.Write {
					names = append(names, g.Repository)
					ids = append(ids, strconv.FormatInt(g.ID, 10))
				}
			}
			if len(names) > 0 {
				caps = append(caps, capabilityFor(access))
				limits[capabilityFor(access)] = map[string]interface{}{repoArgument: names, repoIDArgument: ids}
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

// githubLendData is what one run was lent, as the ledger keeps it in the
// vault: its tokens, so this Identity Agent can withdraw them early, and the
// App and key that made them, so replacing either withdraws them.
type githubLendData struct {
	AppID          int64             `json:"app_id"`
	InstallationID int64             `json:"installation_id"`
	Key            string            `json:"key"`
	Tokens         []githubapp.Token `json:"tokens"`
}

func githubLendDataOf(l lending.Lend) (githubLendData, error) {
	var d githubLendData
	err := json.Unmarshal(l.Data, &d)
	return d, err
}

func (d githubLendData) expires() time.Time {
	var t time.Time
	for _, x := range d.Tokens {
		if x.ExpiresAt.After(t) {
			t = x.ExpiresAt
		}
	}
	return t
}

func (d githubLendData) grants() []repoGrant {
	m := map[int64]repoGrant{}
	for _, t := range d.Tokens {
		for i, id := range t.RepositoryIDs {
			if g, ok := m[id]; ok && g.Access == githubrepo.Write {
				continue
			}
			name := ""
			if i < len(t.Repositories) {
				name = t.Repositories[i]
			}
			m[id] = repoGrant{Repository: name, ID: id, Access: t.Access}
		}
	}
	return sortedGrants(m)
}

// lendableRepos is what may be lent to cc now: the repositories each
// capability's grant names, for each capability that passes the one check.
// Write refused leaves read as its grant gives it.
func (s *CoreServer) lendableRepos(cc permission.CallerContext) map[int64]repoGrant {
	out := map[int64]repoGrant{}
	for _, access := range []githubrepo.Access{githubrepo.Read, githubrepo.Write} {
		capID := capabilityFor(access)
		if ok, _ := s.SandboxManager.MayBeLent(cc, capID); !ok {
			continue
		}
		for id, name := range namedIn(cc.ResourceConstraints, capID) {
			out[id] = repoGrant{Repository: name, ID: id, Access: access}
		}
	}
	return out
}

// githubLendService is GitHub access as a lend: its tokens are withdrawn at
// GitHub, each on its own, so narrowing a grant withdraws only the token that
// gave what was taken away.
func (s *CoreServer) githubLendService() lending.Service {
	return lending.Service{Kind: lendGitHub, IDPrefix: "gl_",
		Check: s.githubLendCheck,
		Parts: func(data json.RawMessage) []json.RawMessage {
			var d githubLendData
			_ = json.Unmarshal(data, &d)
			out := make([]json.RawMessage, 0, len(d.Tokens))
			for _, t := range d.Tokens {
				b, _ := json.Marshal(t)
				out = append(out, b)
			}
			return out
		},
		Withdraw: func(ctx context.Context, part json.RawMessage) error {
			var t githubapp.Token
			if err := json.Unmarshal(part, &t); err != nil {
				return nil
			}
			if err := s.revokeToken(ctx, t); err != nil {
				log.Printf("[github] a token could not be withdrawn at GitHub yet: %v", err)
				return err
			}
			return nil
		},
	}
}

// githubLendCheck says what of a GitHub lend is no longer covered: all of it
// when the App it came from is no longer the one connected — disconnected,
// replaced, or given a new key — when the App cannot be read, or when its AI
// agent or body no longer stand; otherwise each token whose repositories the
// grant no longer gives at that access.
func (s *CoreServer) githubLendCheck(x lending.Lend) *lending.Narrowed {
	d, err := githubLendDataOf(x)
	if err != nil {
		return &lending.Narrowed{Why: "what was lent cannot be read"}
	}
	conn, had, err := s.githubConnection()
	switch {
	case err != nil:
		return &lending.Narrowed{Why: "the organisation's GitHub App cannot be read"}
	case !had:
		return &lending.Narrowed{Why: "the organisation's GitHub App is no longer connected"}
	case conn.AppID != d.AppID || conn.InstallationID != d.InstallationID || conn.KeyFingerprint() != d.Key:
		return &lending.Narrowed{Why: "the organisation's GitHub App was replaced"}
	}
	_, cc, why := s.lentStillCovered(x.Agent, x.Host, "GitHub access")
	if why != "" {
		return &lending.Narrowed{Why: why}
	}
	granted := s.lendableRepos(cc)
	var keep []githubapp.Token
	var gone []json.RawMessage
	var lost []string
	for _, t := range d.Tokens {
		covered := len(t.RepositoryIDs) > 0
		for i, id := range t.RepositoryIDs {
			g, ok := granted[id]
			if !ok || (t.Access == githubrepo.Write && g.Access != githubrepo.Write) {
				covered = false
				name := fmt.Sprint(id)
				if i < len(t.Repositories) {
					name = t.Repositories[i]
				}
				lost = append(lost, fmt.Sprintf("%s %s access", name, t.Access))
			}
		}
		if covered {
			keep = append(keep, t)
			continue
		}
		b, _ := json.Marshal(t)
		gone = append(gone, b)
	}
	if len(gone) == 0 {
		return nil
	}
	why = "its grant no longer gives " + strings.Join(lost, ", ")
	if len(keep) == 0 {
		return &lending.Narrowed{Why: why}
	}
	d.Tokens = keep
	b, _ := json.Marshal(d)
	return &lending.Narrowed{Why: why, Keep: b, Withdraw: gone}
}

// revokeToken withdraws one token at GitHub. One that has lapsed already is
// let go: there is nothing left to withdraw.
func (s *CoreServer) revokeToken(ctx context.Context, t githubapp.Token) error {
	if !time.Now().Before(t.ExpiresAt) {
		return nil
	}
	gh, err := s.githubClient()
	if err != nil {
		return err
	}
	return gh.Revoke(ctx, t.Token)
}

// revokeTokens withdraws tokens at GitHub that were never handed over.
func (s *CoreServer) revokeTokens(ctx context.Context, toks []githubapp.Token) {
	for _, t := range toks {
		if err := s.revokeToken(ctx, t); err != nil {
			log.Printf("[github] a token never handed over could not be withdrawn at GitHub; it lapses within the hour: %v", err)
		}
	}
}

// recordGitHubLendEvent writes what happened to an AI agent's GitHub access
// into the signed record, as the AI agent, naming the body. Never a token.
func (s *CoreServer) recordGitHubLendEvent(a asset.Asset, cc permission.CallerContext, event, status, why string) {
	cc.Transport = firstNonEmptyString(cc.Transport, "body")
	s.recordLentEvent(a, cc, "agent.github."+event, status, why)
}

// ── The body's side ──────────────────────────────────────────────────────────

// handleBodyBorrowsGitHub lends a body GitHub access for one run, each token
// limited to exactly the repositories its AI agent's grant gives it: one that
// reads every repository it may use, and, when it may write some, one for
// those it may write. The read token is made even when it may write every
// one, so a grant narrowed from write to read withdraws only the write token
// and the run keeps reading. A body may name fewer.
//
// A body holds one such lend at a time: whatever it held before is withdrawn.
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
	s.endLendsNoLongerGranted("a body asked for GitHub access")
	if err := s.mayBeLent(a, cc, "GitHub access"); err != nil {
		s.recordGitHubLendEvent(a, cc, "lend", "denied", err.Error())
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}
	if answersOnly(a) {
		why := "this AI agent only reads and answers, and runs nothing that could use GitHub, so none is lent"
		s.recordGitHubLendEvent(a, cc, "lend", "denied", why)
		jsonError(w, why, http.StatusForbidden)
		return
	}
	if len(reposIn(cc.Scopes, cc.ResourceConstraints)) == 0 {
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
		byName := map[string]repoGrant{}
		for _, g := range lendable {
			byName[g.Repository] = g
		}
		narrowed := map[int64]repoGrant{}
		for _, name := range q.Repositories {
			repo, err := githubrepo.NormaliseRepository(name)
			if err != nil {
				jsonError(w, err.Error(), http.StatusBadRequest)
				return
			}
			g, ok := byName[repo]
			if !ok {
				why := "this AI agent's grant does not give it " + repo
				s.recordGitHubLendEvent(a, cc, "lend", "denied", why)
				jsonError(w, why, http.StatusForbidden)
				return
			}
			narrowed[g.ID] = g
		}
		lendable = narrowed
	}
	if len(lendable) == 0 {
		why := "the one check refused every repository this AI agent's grant names"
		for _, access := range []githubrepo.Access{githubrepo.Write, githubrepo.Read} {
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
	var writable, every []githubapp.RepoRef
	for _, g := range sortedGrants(lendable) {
		ref := githubapp.RepoRef{ID: g.ID, Name: g.Repository}
		every = append(every, ref)
		if g.Access == githubrepo.Write {
			writable = append(writable, ref)
		}
	}
	plan := map[githubrepo.Access][]githubapp.RepoRef{}
	if len(writable) > 0 {
		plan[githubrepo.Write] = writable
	}
	plan[githubrepo.Read] = every
	data := githubLendData{AppID: conn.AppID, InstallationID: conn.InstallationID, Key: conn.KeyFingerprint()}
	for _, access := range []githubrepo.Access{githubrepo.Write, githubrepo.Read} {
		repos := plan[access]
		if len(repos) == 0 {
			continue
		}
		tok, err := gh.Mint(ctx, conn, repos, access)
		if err != nil {
			s.revokeTokens(context.WithoutCancel(ctx), data.Tokens)
			s.recordGitHubLendEvent(a, cc, "lend", "error", "GitHub made no token: "+err.Error())
			jsonError(w, "GitHub made no token for this run: "+err.Error(), http.StatusBadGateway)
			return
		}
		data.Tokens = append(data.Tokens, tok)
	}
	raw, _ := json.Marshal(data)
	now := time.Now().UTC()
	lend, ended, err := s.lends().Lend(ctx, lending.Lend{Kind: lendGitHub, Agent: a.ID, Host: b.Host,
		Expires: data.expires(), Data: raw}, lending.Limit{OnePerBody: true}, now)
	s.recordEnded(ended, "")
	if err != nil {
		// A token this Identity Agent could not withdraw later is not lent.
		s.revokeTokens(context.WithoutCancel(ctx), data.Tokens)
		jsonError(w, "the lend could not be recorded, so nothing was lent: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	// A grant, body or App that changed while GitHub was making the tokens
	// found nothing lent yet to withdraw. Checked again now the lend is
	// recorded, so such a lend is withdrawn rather than handed over — and if
	// what is lent, or the App, cannot be read to check it, it is withdrawn too.
	s.endLendsNoLongerGranted("GitHub access was just lent")
	held, found, err := s.lends().Find(lendGitHub, lend.ID, b.Host, a.ID, time.Now().UTC())
	if err != nil || !found || !held.IsOpen(time.Now().UTC()) || !bytes.Equal(held.Data, raw) {
		why := "this AI agent's grant changed while GitHub access was being lent, so it was withdrawn"
		if err != nil {
			why = "what was lent could not be checked again, so it was withdrawn: " + err.Error()
		}
		if _, rerr := s.lends().Return(context.WithoutCancel(ctx), lendGitHub, lend.ID, b.Host, a.ID, time.Now().UTC()); rerr != nil {
			s.revokeTokens(context.WithoutCancel(ctx), data.Tokens)
		}
		s.recordGitHubLendEvent(a, cc, "lend", "denied", why)
		jsonError(w, why, http.StatusForbidden)
		return
	}
	var parts []string
	tokens := make([]map[string]any, 0, len(data.Tokens))
	for _, t := range data.Tokens {
		parts = append(parts, fmt.Sprintf("%s %s", strings.Join(t.Repositories, ", "), t.Access))
		tokens = append(tokens, map[string]any{"access": t.Access, "repositories": t.Repositories,
			"token": t.Token, "expires_at": t.ExpiresAt})
	}
	s.recordGitHubLendEvent(a, cc, "lent", "ok", fmt.Sprintf("lend %s: %s, until %s",
		lend.ID, strings.Join(parts, "; "), data.expires().Format(time.RFC3339)))
	name := firstNonEmptyString(a.DisplayName, "AI agent")
	// This answer travels sealed to the keys the body enrolled with: the
	// route is reached only through the sealed transport (theBodyAsking).
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"lend_id": lend.ID, "expires_at": data.expires(), "git_host": githubapp.DefaultGitHost,
		"author_name": name, "author_email": conn.BotEmail(), "commits_as": conn.BotName(),
		"tokens": tokens,
	})
}

// handleBodyReturnsGitHub takes a run's GitHub access back, and withdraws its
// tokens at GitHub. One GitHub cannot be reached for is tried again, every
// minute, until it lapses. A body that started again gives back, with every,
// whatever it held before.
func (s *CoreServer) handleBodyReturnsGitHub(w http.ResponseWriter, r *http.Request) {
	cc, b, a, ok := s.theBodyAndItsAgent(w, r)
	if !ok {
		return
	}
	var q struct {
		LendID string `json:"lend_id"`
		Every  bool   `json:"every"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&q); err != nil || (q.LendID == "" && !q.Every) {
		jsonError(w, "name the lend to return", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	now := time.Now().UTC()
	var got []lending.Returned
	var err error
	if q.Every {
		got, err = s.lends().ReturnEvery(ctx, lendGitHub, b.Host, a.ID, now)
	} else {
		var one lending.Returned
		one, err = s.lends().Return(ctx, lendGitHub, q.LendID, b.Host, a.ID, now)
		got = []lending.Returned{one}
	}
	if errors.Is(err, lending.ErrNoLend) {
		writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": "this body holds no such lend", "no_lend": true})
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	all := true
	for _, x := range got {
		why := "lend " + x.Lend.ID + " returned and its tokens withdrawn at GitHub"
		status := "ok"
		if !x.Withdrawn {
			all = false
			why = "lend " + x.Lend.ID + " returned; GitHub could not be reached to withdraw its tokens yet, so it is tried again until they lapse"
			status = "error"
		}
		if q.Every {
			why += ", as its body started again"
		}
		s.recordGitHubLendEvent(a, cc, "returned", status, why)
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"returned": len(got), "withdrawn": all})
}
