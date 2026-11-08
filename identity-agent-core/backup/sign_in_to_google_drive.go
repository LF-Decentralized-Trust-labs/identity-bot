package backup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"identity-agent-core/backup/remote"
)

// Signing in to Google so the Identity Agent can keep an archive in the
// person's Drive.
//
// WHO DOES WHAT. The core never opens a browser and never listens for Google's
// redirect: the app does both (a loopback listener or a custom-scheme handler
// it registered with Google), and hands the core only the code Google returned.
// That keeps this off the core's HTTP surface for a browser to reach.
//
//	app  -> core   StartGoogleSignIn(redirect)      returns the URL to open
//	app  -> Google (the person signs in and consents to ONE scope)
//	app  -> core   CompleteGoogleSignIn(state, code, redirect)
//
// The flow is the installed-app one with PKCE, so the code is useless to anyone
// who sees it but the core that asked for it.

// GoogleProviderName is the cloud_provider a Drive destination carries.
const GoogleProviderName = "google_drive"

// Where the app's own OAuth client comes from. Neither is a secret in the
// installed-app flow (Google documents the "secret" of a desktop client as
// not confidential), and the id is public; they are configuration of the
// build, supplied by whoever owns the Google Cloud project.
const (
	GoogleClientIDEnv     = "IDENTITY_GOOGLE_OAUTH_CLIENT_ID"
	GoogleClientSecretEnv = "IDENTITY_GOOGLE_OAUTH_CLIENT_SECRET"
)

// GoogleSignIn holds the OAuth client and where Google's endpoints are. The
// zero value reads the client from the environment and talks to Google.
type GoogleSignIn struct {
	ClientID     string
	ClientSecret string
	AuthURL      string
	Endpoints    remote.GoogleEndpoints
	HTTP         *http.Client

	mu      sync.Mutex
	pending map[string]pendingSignIn
	now     func() time.Time
}

type pendingSignIn struct {
	verifier string
	redirect string
	expires  time.Time
}

const (
	signInLifetime = 10 * time.Minute
	maxPending     = 16
)

func (g *GoogleSignIn) client() (id, secret string, err error) {
	id, secret = g.ClientID, g.ClientSecret
	if id == "" {
		id, secret = os.Getenv(GoogleClientIDEnv), os.Getenv(GoogleClientSecretEnv)
	}
	if id == "" {
		return "", "", fmt.Errorf("Google Drive backup is not set up in this build: no Google OAuth client id (%s)", GoogleClientIDEnv)
	}
	return id, secret, nil
}

func (g *GoogleSignIn) clock() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}

// redirectAllowed: a loopback address over http, or an app's own custom scheme.
// Never a web address, so a code cannot be sent to a site.
func redirectAllowed(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return fmt.Errorf("redirect_uri is not a valid address")
	}
	switch u.Scheme {
	case "https":
		return fmt.Errorf("redirect_uri must be a loopback address or the app's own scheme, not a web address")
	case "http":
		switch u.Hostname() {
		case "127.0.0.1", "localhost", "::1":
			return nil
		}
		return fmt.Errorf("redirect_uri over http must be a loopback address")
	}
	// An app's own scheme is reverse-DNS (com.example.app), which no browser
	// treats as a built-in one.
	switch u.Scheme {
	case "javascript", "file", "data", "ftp", "blob", "about":
		return fmt.Errorf("redirect_uri scheme %q is not an app's own", u.Scheme)
	}
	if !strings.Contains(u.Scheme, ".") {
		return fmt.Errorf("redirect_uri must use a reverse-DNS app scheme (like com.example.app)")
	}
	return nil
}

func randomURLString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// StartGoogleSignIn returns the address the app opens for the person to sign in
// and the state that comes back with the code.
func (s *Service) StartGoogleSignIn(redirectURI string) (authURL, state string, err error) {
	g := s.googleSignIn()
	id, _, err := g.client()
	if err != nil {
		return "", "", err
	}
	if err := redirectAllowed(redirectURI); err != nil {
		return "", "", err
	}
	verifier, err := randomURLString(48)
	if err != nil {
		return "", "", err
	}
	if state, err = randomURLString(24); err != nil {
		return "", "", err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pending == nil {
		g.pending = map[string]pendingSignIn{}
	}
	now := g.clock()
	for k, p := range g.pending {
		if now.After(p.expires) {
			delete(g.pending, k)
		}
	}
	if len(g.pending) >= maxPending {
		return "", "", fmt.Errorf("too many sign-ins in progress, try again shortly")
	}
	g.pending[state] = pendingSignIn{verifier: verifier, redirect: redirectURI, expires: now.Add(signInLifetime)}
	challenge := sha256.Sum256([]byte(verifier))
	base := g.AuthURL
	if base == "" {
		base = "https://accounts.google.com/o/oauth2/v2/auth"
	}
	q := url.Values{
		"client_id":             {id},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {remote.GoogleAppDataScope},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
		// Offline, and consent shown again, because Google issues a refresh
		// token only on the first consent otherwise: a person re-adding Drive
		// on a new machine would get nothing that outlives an hour.
		"access_type": {"offline"},
		"prompt":      {"consent"},
	}
	return base + "?" + q.Encode(), state, nil
}

// CompleteGoogleSignIn exchanges the code, keeps the grant with the other
// secrets, and makes (or renews) the Drive destination.
func (s *Service) CompleteGoogleSignIn(state, code, redirectURI string) (Destination, error) {
	g := s.googleSignIn()
	id, secret, err := g.client()
	if err != nil {
		return Destination{}, err
	}
	if s.CredentialStore == nil {
		return Destination{}, fmt.Errorf("credential store unavailable")
	}
	g.mu.Lock()
	p, ok := g.pending[state]
	delete(g.pending, state) // one use, whatever happens next
	g.mu.Unlock()
	if !ok || g.clock().After(p.expires) {
		return Destination{}, fmt.Errorf("this sign-in was not started here or has timed out, start again")
	}
	if redirectURI != p.redirect {
		return Destination{}, fmt.Errorf("redirect_uri differs from the one the sign-in started with")
	}
	if code == "" {
		return Destination{}, fmt.Errorf("no authorisation code")
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.redirect},
		"client_id":     {id},
		"code_verifier": {p.verifier},
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	tokenURL := g.Endpoints.Token
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	hc := g.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Destination{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return Destination{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		Error        string `json:"error"`
	}
	_ = json.Unmarshal(body, &tok)
	if resp.StatusCode != http.StatusOK {
		return Destination{}, fmt.Errorf("google refused the sign-in: %s", tok.Error)
	}
	// Whatever is received and then refused is cancelled at Google, so a refused
	// grant does not stay live in the person's account.
	refuse := func() {
		rctx, rcancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer rcancel()
		remote.RevokeGoogleToken(rctx, g.Endpoints, g.HTTP, tok.RefreshToken)
		remote.RevokeGoogleToken(rctx, g.Endpoints, g.HTTP, tok.AccessToken)
	}
	if tok.RefreshToken == "" {
		refuse()
		return Destination{}, fmt.Errorf("google gave no long-lived sign-in, so backups could not continue after an hour; try again")
	}
	// The person can untick a scope on the consent screen, and a client can be
	// configured for more than was asked. Keep the grant only if it is exactly
	// what a backup needs: able to do the job, and nothing wider.
	granted := strings.Fields(tok.Scope)
	if len(granted) != 1 || granted[0] != remote.GoogleAppDataScope {
		refuse()
		return Destination{}, fmt.Errorf("the sign-in was not for exactly the app's own backup folder (got %q), so it was not kept", tok.Scope)
	}

	cfg, err := s.ConfigStore.LoadConfig()
	if err != nil {
		return Destination{}, err
	}
	dest := Destination{
		ID: "google-drive", Type: DestCloudUser, Label: "Google Drive",
		CloudProvider: GoogleProviderName, CloudPrefix: s.ownAID(),
		// Reading it back needs a Google sign-in and the recovery words, not this
		// agent: it is not gated on a working Identity Agent.
		IAGated: false, Enabled: true,
	}
	var previousCred string
	for _, d := range cfg.Destinations {
		if d.ID == dest.ID {
			previousCred = d.CredentialID
			dest.LastSuccessAt, dest.LastFullAt = d.LastSuccessAt, d.LastFullAt
			if dest.CloudPrefix == "" {
				dest.CloudPrefix = d.CloudPrefix
			}
		}
	}
	credID, err := s.SaveDestinationCredentials(RemoteCredentialSecrets{
		OAuthRefreshToken: tok.RefreshToken, OAuthClientID: id, OAuthClientSecret: secret,
	})
	if err != nil {
		return Destination{}, err
	}
	dest.CredentialID = credID
	UpsertDestination(&cfg, dest)
	if err := s.ConfigStore.SaveConfig(cfg); err != nil {
		_ = s.CredentialStore.Delete(credID)
		return Destination{}, err
	}
	if previousCred != "" {
		_ = s.CredentialStore.Delete(previousCred)
	}
	return dest, nil
}

// RemoveDestination takes a destination out of the configuration and lets go of
// what was given to reach it: the sign-in is cancelled at Google, where
// removing it here alone would leave the grant live in the person's account,
// and the credential file is deleted. Cancelling is best effort — an
// unreachable Google must not make it impossible to remove a destination — and
// the person can always remove the app in their Google account.
//
// Reports whether there was such a destination.
func (s *Service) RemoveDestination(id string) (bool, error) {
	cfg, err := s.ConfigStore.LoadConfig()
	if err != nil {
		return false, err
	}
	var gone *Destination
	kept := []Destination{}
	for i := range cfg.Destinations {
		if cfg.Destinations[i].ID == id {
			d := cfg.Destinations[i]
			gone = &d
			continue
		}
		kept = append(kept, cfg.Destinations[i])
	}
	cfg.Destinations = kept
	if err := s.ConfigStore.SaveConfig(cfg); err != nil {
		return false, err
	}
	if gone == nil || gone.CredentialID == "" || s.CredentialStore == nil {
		return gone != nil, nil
	}
	if gone.CloudProvider == GoogleProviderName {
		if creds, lerr := s.CredentialStore.Load(gone.CredentialID); lerr == nil {
			g := s.googleSignIn()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			remote.RevokeGoogleToken(ctx, g.Endpoints, g.HTTP, creds.OAuthRefreshToken)
		}
	}
	return true, s.CredentialStore.Delete(gone.CredentialID)
}

func (s *Service) googleSignIn() *GoogleSignIn {
	s.googleOnce.Do(func() {
		if s.Google == nil {
			s.Google = &GoogleSignIn{}
		}
	})
	return s.Google
}

// onlyOneArchiveOwner: a Drive that holds archives of more than one identity
// cannot be restored from without saying which. Called with no prefix, which is
// a machine that has just signed in and does not know whose archive it wants.
func onlyOneArchiveOwner(keys []string) error {
	owners := map[string]bool{}
	for _, k := range keys {
		if !strings.HasSuffix(k, ".iab") {
			continue
		}
		owner := ""
		if i := strings.Index(k, "/"); i >= 0 {
			owner = k[:i]
		}
		owners[owner] = true
	}
	if len(owners) > 1 {
		return fmt.Errorf("this Google Drive holds backups of more than one identity; say which one to restore")
	}
	return nil
}
