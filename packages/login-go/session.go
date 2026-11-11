package login

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Front-end kinds a sign-in may name (ADR-072 section 2).
const (
	FrontEndBrowser      = "browser"
	FrontEndInstalledApp = "installed_app"
)

const (
	maxAnswer = 1 << 20
	// DefaultSpentFor is how long a spent sign-in is remembered: the Identity
	// Agent offers a challenge for ten minutes, so it cannot be answered later
	// than that and confirmed later still than the poll that follows.
	DefaultSpentFor = time.Hour
)

// StartOptions asks for a sign-in.
type StartOptions struct {
	// AgentURL is the Identity Agent that holds the asset.
	AgentURL string
	// AssetID is the asset the sign-in is on.
	AssetID string
	// Audience is the site's own origin. The person's approval is for it alone.
	Audience           string
	RequestDisclosures []string
	// BrowserKey is the thumbprint of a key the person's browser holds, when the
	// sign-in is for that key (ADR-066).
	BrowserKey string
	// FrontEnd is FrontEndBrowser or FrontEndInstalledApp, for a utility app's
	// sign-in. Left empty for a website asset.
	FrontEnd string
	// Client is the HTTP client; http.DefaultClient when nil.
	Client *http.Client
}

// Started is a sign-in the Identity Agent has begun.
type Started struct {
	// SessionToken names the sign-in and travels in the pointer.
	SessionToken string
	// PointerUrl is what to show the person: scanning it opens the sign-in in
	// their Identity Agent.
	PointerUrl string
	// CollectorSecret stays on the server. ConfirmSession needs it to read who
	// signed in. Keep it out of the page and out of any link.
	CollectorSecret string
}

func base(agentURL string) string { return strings.TrimSuffix(agentURL, "/") }

// escape is encodeURIComponent for one path segment.
func escape(s string) string { return strings.ReplaceAll(url.PathEscape(s), "+", "%2B") }

func client(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return http.DefaultClient
}

// StartSession asks the Identity Agent for a sign-in on the asset. A refusal
// (the asset not found, a front end the owner switched off) is an error that
// carries the Identity Agent's words.
func StartSession(ctx context.Context, o StartOptions) (Started, error) {
	b := base(o.AgentURL)
	disclosures := o.RequestDisclosures
	if disclosures == nil {
		disclosures = []string{}
	}
	body := map[string]any{"audience": o.Audience, "requestDisclosures": disclosures}
	if o.BrowserKey != "" {
		body["browserKey"] = o.BrowserKey
	}
	if o.FrontEnd != "" {
		body["frontEnd"] = o.FrontEnd
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return Started{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b+"/api/login/session/"+escape(o.AssetID), bytes.NewReader(raw))
	if err != nil {
		return Started{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client(o.Client).Do(req)
	if err != nil {
		return Started{}, fmt.Errorf("login: the Identity Agent at %s could not be reached: %w", b, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		why := strings.TrimSpace(string(data))
		if why != "" {
			why = ": " + why
		}
		return Started{}, fmt.Errorf("login: the Identity Agent at %s would not start a sign-in (%d%s)", b, resp.StatusCode, why)
	}
	var out struct {
		SessionToken    string `json:"session_token"`
		Pointer         string `json:"relay_or_qr_url"`
		CollectorSecret string `json:"collector_secret"`
	}
	if json.Unmarshal(data, &out) != nil || out.SessionToken == "" || out.Pointer == "" || out.CollectorSecret == "" {
		return Started{}, fmt.Errorf("login: the Identity Agent at %s answered a sign-in without a token, pointer and secret", b)
	}
	return Started{SessionToken: out.SessionToken, PointerUrl: out.Pointer, CollectorSecret: out.CollectorSecret}, nil
}

// Spent spends a verified sign-in so the same one signs nobody in twice.
// Claim reports true the first time a key is claimed. keepUntil is when the
// store may forget it. A site on more than one process shares one store.
type Spent interface {
	Claim(key string, keepUntil time.Time) (bool, error)
}

// ConfirmOptions asks how a sign-in went.
type ConfirmOptions struct {
	AgentURL     string
	AssetID      string
	SessionToken string
	// CollectorSecret is what StartSession returned. Without it the Identity
	// Agent reports the state but withholds who signed in.
	CollectorSecret string
	// Spent, when set, spends a verified session: confirming it again is an
	// error. A site that issues its own session on Verified should pass one.
	Spent Spent
	// SpentFor is how long a spent sign-in is remembered; DefaultSpentFor when zero.
	SpentFor time.Duration
	Client   *http.Client
	// Now is the clock; time.Now when nil.
	Now func() time.Time
}

// State is how a sign-in stands.
type State string

const (
	Verified State = "verified"
	Declined State = "declined"
	Pending  State = "pending"
)

// MemberInfo is who the admitting roster says a member is.
type MemberInfo struct {
	Role        string
	DisplayName string
}

// Confirmed is how a sign-in stands. Only a Verified one names a person.
type Confirmed struct {
	State State
	// PairwiseAID is who signed in, on Verified.
	PairwiseAID string
	Disclosures map[string]any
	MemberInfo  *MemberInfo
	// BrowserKey is the browser key the person's approval named (ADR-066), when
	// the sign-in was for one. A back end that binds its session to a browser's
	// key lets that browser in only when this is the thumbprint it started the
	// sign-in with.
	BrowserKey string
	// FrontEnd is the front-end kind the verified assertion repeated (ADR-072).
	FrontEnd string
	// Reason is why a sign-in was declined.
	Reason string
}

// ErrAlreadyUsed is returned when a verified sign-in has been confirmed before.
var ErrAlreadyUsed = errors.New("login: this sign-in has already been used")

// ConfirmSession asks the Identity Agent how the sign-in stands. Issue an
// application session only on Verified. An answer that is not ok, or that
// verifies nobody, is Pending, never Verified.
func ConfirmSession(ctx context.Context, o ConfirmOptions) (Confirmed, error) {
	b := base(o.AgentURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b+"/api/login/session/"+escape(o.AssetID)+"/"+escape(o.SessionToken), nil)
	if err != nil {
		return Confirmed{}, err
	}
	req.Header.Set("Accept", "application/json")
	if o.CollectorSecret != "" {
		req.Header.Set("X-Collector-Secret", o.CollectorSecret)
	}
	resp, err := client(o.Client).Do(req)
	if err != nil {
		return Confirmed{}, fmt.Errorf("login: the Identity Agent at %s could not be reached: %w", b, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Confirmed{State: Pending}, nil
	}
	var body struct {
		State            string         `json:"state"`
		AppSessionToken  string         `json:"app_session_token"`
		Disclosures      map[string]any `json:"disclosures"`
		Reason           string         `json:"reason"`
		BrowserKey       string         `json:"browser_key"`
		FrontEnd         string         `json:"front_end"`
		IdentityWithheld bool           `json:"identity_withheld"`
		MemberInfo       *struct {
			Role        string `json:"role"`
			DisplayName string `json:"display_name"`
		} `json:"member_info"`
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	if json.Unmarshal(data, &body) != nil {
		return Confirmed{State: Pending}, nil
	}
	// Verified, but this caller could not collect: pending would spin forever
	// and verified would hand back an empty identity.
	if body.State == "verified" && body.IdentityWithheld {
		return Confirmed{}, errors.New("login: the Identity Agent withheld the identity — pass the collectorSecret returned when the session was created")
	}
	if body.State == "verified" && body.AppSessionToken != "" {
		if o.Spent != nil {
			now := time.Now
			if o.Now != nil {
				now = o.Now
			}
			keep := o.SpentFor
			if keep <= 0 {
				keep = DefaultSpentFor
			}
			fresh, err := o.Spent.Claim(b+"|"+o.AssetID+"|"+o.SessionToken, now().Add(keep))
			if err != nil {
				return Confirmed{}, fmt.Errorf("login: the spent-sign-in store failed: %w", err)
			}
			if !fresh {
				return Confirmed{}, ErrAlreadyUsed
			}
		}
		c := Confirmed{State: Verified, PairwiseAID: body.AppSessionToken, Disclosures: body.Disclosures, BrowserKey: body.BrowserKey, FrontEnd: body.FrontEnd}
		if body.MemberInfo != nil {
			c.MemberInfo = &MemberInfo{Role: body.MemberInfo.Role, DisplayName: body.MemberInfo.DisplayName}
		}
		return c, nil
	}
	if body.State == "declined" {
		return Confirmed{State: Declined, Reason: body.Reason}, nil
	}
	return Confirmed{State: Pending}, nil
}

// InMemorySpent is a Spent that forgets on restart and lives in one process.
// A site that restarts, or runs several processes, supplies its own.
type InMemorySpent struct {
	mu   sync.Mutex
	seen map[string]time.Time
	Now  func() time.Time
}

// Claim implements Spent. Entries past their keepUntil are dropped as it goes.
func (s *InMemorySpent) Claim(key string, keepUntil time.Time) (bool, error) {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]time.Time{}
	}
	t := now()
	for k, until := range s.seen {
		if !until.After(t) {
			delete(s.seen, k)
		}
	}
	if _, used := s.seen[key]; used {
		return false, nil
	}
	s.seen[key] = keepUntil
	return true, nil
}
