// Package githubapp is how an Identity Agent uses a GitHub App that its
// organisation connected once: the App's private key signs a short request
// for an installation token, limited to chosen repositories and permissions,
// which the Identity Agent lends to an AI agent's body for one run and
// withdraws when the run ends.
//
// The private key never leaves the Identity Agent's vault. Nothing here keeps
// anything; the caller does, in the vault.
package githubapp

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
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"identity-agent-core/githubrepo"
)

// DefaultAPI is GitHub's API. An Identity Agent reaches no other: the address
// is not something a request can set, so connecting an App cannot be used to
// make the Identity Agent send a signed request somewhere else.
const DefaultAPI = "https://api.github.com"

// DefaultGitHost is where git reaches GitHub's repositories.
const DefaultGitHost = "github.com"

// Connection is what an organisation's GitHub App is, as the vault keeps it.
// PrivateKey is the App's key, as GitHub gave it; it is never returned.
type Connection struct {
	AppID          int64  `json:"app_id"`
	InstallationID int64  `json:"installation_id"`
	PrivateKey     string `json:"private_key"`
	// What GitHub said the App and its installation are, when it was
	// connected.
	AppSlug   string `json:"app_slug,omitempty"`
	AppName   string `json:"app_name,omitempty"`
	BotUserID int64  `json:"bot_user_id,omitempty"`
	// Account is the GitHub organisation or user the App is installed on.
	// Every repository it can reach is that account's.
	Account     string    `json:"account,omitempty"`
	ConnectedAt time.Time `json:"connected_at"`
}

// KeyFingerprint names the App's key without showing it: a digest of its
// public half, as hex, so a person can tell which key is in use.
func (c Connection) KeyFingerprint() string {
	k, err := ParsePrivateKey(c.PrivateKey)
	if err != nil {
		return ""
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return fmt.Sprintf("SHA256:%x", sum[:8])
}

// BotName is who commits and pushes appear as on GitHub.
func (c Connection) BotName() string {
	if c.AppSlug == "" {
		return ""
	}
	return c.AppSlug + "[bot]"
}

// BotEmail is the address GitHub links to the App's bot account, so a commit
// with it is shown as the App's.
func (c Connection) BotEmail() string {
	if c.AppSlug == "" {
		return ""
	}
	if c.BotUserID > 0 {
		return fmt.Sprintf("%d+%s[bot]@users.noreply.github.com", c.BotUserID, c.AppSlug)
	}
	return c.AppSlug + "[bot]@users.noreply.github.com"
}

// ParsePrivateKey reads a GitHub App's private key, as the .pem file GitHub
// gives (PKCS#1), or as PKCS#8.
func ParsePrivateKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemText)))
	if block == nil {
		return nil, errors.New("this is not a private key file: it has no PEM block")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, checkSize(k)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("this is not a GitHub App's private key: it is not an RSA private key")
	}
	k, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("this is not a GitHub App's private key: GitHub's are RSA keys")
	}
	return k, checkSize(k)
}

func checkSize(k *rsa.PrivateKey) error {
	if k.N.BitLen() < 2048 {
		return errors.New("this key is too short to be a GitHub App's private key")
	}
	return nil
}

// AppJWT is the short statement, signed with the App's key (RS256), that
// GitHub takes as the App itself. It holds for nine minutes, from a minute
// before now in case the clocks disagree; GitHub refuses one that holds for
// more than ten.
func AppJWT(key *rsa.PrivateKey, appID int64, now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": strconv.FormatInt(appID, 10),
	})
	if err != nil {
		return "", err
	}
	signing := header + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// Sender sends a request to GitHub. The Identity Agent sends it through its
// governed way out, with the same policy check, log and trace as its own
// calls; a test sends it to a stand-in.
type Sender func(ctx context.Context, req *http.Request, client *http.Client) (*http.Response, error)

// Client talks to GitHub's API as an App.
type Client struct {
	// API is GitHub's API address. Empty is DefaultAPI.
	API  string
	Send Sender
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

func (c Client) api() string {
	if c.API == "" {
		return DefaultAPI
	}
	return strings.TrimRight(c.API, "/")
}

func (c Client) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

// noRedirects sends a request and follows no redirect, so a token goes only
// to the address it was meant for.
var noRedirects = &http.Client{
	Timeout:       20 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// APIError is GitHub refusing a request: its status, and its own reason.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("GitHub answered %d", e.Status)
	}
	return fmt.Sprintf("GitHub answered %d: %s", e.Status, e.Message)
}

// call sends one request, with auth as its Authorization, and reads a JSON
// answer into out when the status is want.
func (c Client) call(ctx context.Context, method, path, auth string, body any, want int, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.api()+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "identity-agent")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	send := c.Send
	if send == nil {
		send = func(ctx context.Context, req *http.Request, client *http.Client) (*http.Response, error) {
			return client.Do(req.WithContext(ctx))
		}
	}
	resp, err := send(ctx, req, noRedirects)
	if err != nil {
		return fmt.Errorf("GitHub could not be reached: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != want {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := e.Message
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return &APIError{Status: resp.StatusCode, Message: msg}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("GitHub's answer is unreadable: %w", err)
	}
	return nil
}

func (c Client) asApp(conn Connection) (string, error) {
	key, err := ParsePrivateKey(conn.PrivateKey)
	if err != nil {
		return "", err
	}
	jwt, err := AppJWT(key, conn.AppID, c.now())
	if err != nil {
		return "", err
	}
	return "Bearer " + jwt, nil
}

// Describe asks GitHub what the App and its installation are, which also
// proves the key is the App's and the installation is that App's. It fills in
// the connection's slug, name, bot and account.
func (c Client) Describe(ctx context.Context, conn Connection) (Connection, error) {
	if conn.AppID <= 0 || conn.InstallationID <= 0 {
		return conn, errors.New("a GitHub App is named by its App ID and installation ID, both numbers")
	}
	auth, err := c.asApp(conn)
	if err != nil {
		return conn, err
	}
	var app struct {
		ID   int64  `json:"id"`
		Slug string `json:"slug"`
		Name string `json:"name"`
	}
	if err := c.call(ctx, "GET", "/app", auth, nil, http.StatusOK, &app); err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == http.StatusUnauthorized {
			return conn, errors.New("GitHub did not accept this private key for that App ID")
		}
		return conn, err
	}
	if app.ID != conn.AppID {
		return conn, fmt.Errorf("this private key is for App %d, not App %d", app.ID, conn.AppID)
	}
	var inst struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
	}
	if err := c.call(ctx, "GET", fmt.Sprintf("/app/installations/%d", conn.InstallationID), auth, nil,
		http.StatusOK, &inst); err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
			return conn, fmt.Errorf("App %d has no installation %d", conn.AppID, conn.InstallationID)
		}
		return conn, err
	}
	conn.AppSlug, conn.AppName, conn.Account = app.Slug, app.Name, strings.ToLower(inst.Account.Login)
	// The bot's account number makes commits show as the App's. Asked
	// without the key: it is public, and a failure costs only that.
	var bot struct {
		ID int64 `json:"id"`
	}
	if app.Slug != "" && c.call(ctx, "GET", "/users/"+url.PathEscape(app.Slug+"[bot]"), "", nil,
		http.StatusOK, &bot) == nil {
		conn.BotUserID = bot.ID
	}
	return conn, nil
}

// Token is an installation token GitHub made.
type Token struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	// Repositories are the repositories GitHub says it works for, as
	// owner/name, and RepositoryIDs the same by GitHub's own numbers, which a
	// repository deleted and made again under the same name does not keep.
	Repositories  []string          `json:"repositories"`
	RepositoryIDs []int64           `json:"repository_ids"`
	Access        githubrepo.Access `json:"access"`
}

// RepoRef is a repository by GitHub's number for it, and its name.
type RepoRef struct {
	ID   int64
	Name string
}

// Mint asks GitHub for an installation token that works only for repos — by
// GitHub's numbers for them, so a repository deleted and made again under the
// same name is not one of them — with access's permissions. GitHub's answer is
// checked to be no wider than asked: it must name only those repositories, as
// a selection, and grant exactly the permissions asked. A token that is wider
// is withdrawn and refused.
func (c Client) Mint(ctx context.Context, conn Connection, repos []RepoRef, access githubrepo.Access) (Token, error) {
	if len(repos) == 0 {
		return Token{}, errors.New("a token is asked for at least one repository")
	}
	ids := make([]int64, 0, len(repos))
	// want is the name the grant gives each number: GitHub's answer must name
	// each repository it made the token for by that same name, so a grant that
	// pairs one repository's name with another's number lends neither.
	want := map[int64]string{}
	for _, r := range repos {
		if r.ID <= 0 {
			return Token{}, fmt.Errorf("%s is not named by GitHub's number for it", r.Name)
		}
		owner, _, _ := strings.Cut(r.Name, "/")
		if conn.Account != "" && !strings.EqualFold(owner, conn.Account) {
			return Token{}, fmt.Errorf("%s is not %s's, where the GitHub App is installed", r.Name, conn.Account)
		}
		if _, twice := want[r.ID]; twice {
			return Token{}, fmt.Errorf("GitHub's number %d is given for more than one repository", r.ID)
		}
		ids = append(ids, r.ID)
		want[r.ID] = strings.ToLower(r.Name)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	auth, err := c.asApp(conn)
	if err != nil {
		return Token{}, err
	}
	var out struct {
		Token        string    `json:"token"`
		ExpiresAt    time.Time `json:"expires_at"`
		Selection    string    `json:"repository_selection"`
		Repositories []struct {
			ID       int64  `json:"id"`
			FullName string `json:"full_name"`
		} `json:"repositories"`
		Permissions map[string]string `json:"permissions"`
	}
	body := map[string]any{"repository_ids": ids, "permissions": access.Permissions()}
	if err := c.call(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", conn.InstallationID),
		auth, body, http.StatusCreated, &out); err != nil {
		return Token{}, err
	}
	tok := Token{Token: out.Token, ExpiresAt: out.ExpiresAt, Access: access}
	why := ""
	switch {
	case out.Token == "":
		why = "GitHub made no token"
	case out.Selection != "selected":
		why = "GitHub made a token for every repository the App can reach, not the ones asked for"
	case len(out.Repositories) == 0:
		why = "GitHub's answer names no repository the token works for"
	}
	for _, r := range out.Repositories {
		name, asked := want[r.ID]
		switch {
		case !asked:
			why = "GitHub made a token for more repositories than were asked for"
		case !strings.EqualFold(r.FullName, name):
			why = fmt.Sprintf("GitHub's repository %d is %s, not the %s it was granted as", r.ID, strings.ToLower(r.FullName), name)
		}
		tok.Repositories = append(tok.Repositories, strings.ToLower(r.FullName))
		tok.RepositoryIDs = append(tok.RepositoryIDs, r.ID)
	}
	asked := access.Permissions()
	for p, level := range out.Permissions {
		if asked[p] != level {
			why = fmt.Sprintf("GitHub gave the token %s %q, where %q was asked for", p, level, asked[p])
		}
	}
	if why != "" {
		if out.Token != "" {
			_ = c.Revoke(ctx, out.Token)
		}
		return Token{}, errors.New(why + ", so it was withdrawn")
	}
	if tok.ExpiresAt.IsZero() {
		tok.ExpiresAt = c.now().Add(time.Hour)
	}
	return tok, nil
}

// Revoke withdraws an installation token at GitHub, before it would expire.
// A token already gone (GitHub answers 401) counts as withdrawn.
func (c Client) Revoke(ctx context.Context, token string) error {
	err := c.call(ctx, "DELETE", "/installation/token", "Bearer "+token, nil, http.StatusNoContent, nil)
	var ae *APIError
	if errors.As(err, &ae) && ae.Status == http.StatusUnauthorized {
		return nil
	}
	return err
}

// Repository is one repository the App can reach, as a screen shows it.
type Repository struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
}

// Repositories lists every repository the installation can reach. It asks
// for a read-only token to do so, and withdraws it straight after.
func (c Client) Repositories(ctx context.Context, conn Connection) ([]Repository, error) {
	auth, err := c.asApp(conn)
	if err != nil {
		return nil, err
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := c.call(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", conn.InstallationID),
		auth, map[string]any{"permissions": map[string]string{"metadata": "read"}}, http.StatusCreated, &tok); err != nil {
		return nil, err
	}
	defer func() { _ = c.Revoke(context.WithoutCancel(ctx), tok.Token) }()
	// Every page, however many there are: a repository left off would be one
	// nobody could grant. An answer with no repositories ends it, so a GitHub
	// that miscounts cannot keep this asking.
	var out []Repository
	for page := 1; ; page++ {
		var res struct {
			TotalCount   int          `json:"total_count"`
			Repositories []Repository `json:"repositories"`
		}
		if err := c.call(ctx, "GET", fmt.Sprintf("/installation/repositories?per_page=100&page=%d", page),
			"Bearer "+tok.Token, nil, http.StatusOK, &res); err != nil {
			return nil, err
		}
		for _, r := range res.Repositories {
			r.FullName = strings.ToLower(r.FullName)
			out = append(out, r)
		}
		if len(res.Repositories) == 0 || (res.TotalCount > 0 && len(out) >= res.TotalCount) ||
			(res.TotalCount == 0 && len(res.Repositories) < 100) {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName < out[j].FullName })
	return out, nil
}
