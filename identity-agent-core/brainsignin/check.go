package brainsignin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Checking a sign-in works before it is kept.
//
// One request is made, to the provider's cheapest question that needs the key
// and sends nothing of anybody's: which models it may use, or what the key
// itself is. No model is run and no words leave. The answer says whether the
// provider accepted it and, where the provider says, which account it is.
//
// Two kinds are not sent anywhere by the Identity Agent:
//
//   - A Claude subscription's token is for Claude Code alone; the Identity
//     Agent never uses it itself. Claude Code on the computer that signed it in
//     checks it.
//   - A Codex or Grok sign-in is the file the program wrote when the person
//     signed in, which proves it worked then. It is read here, for its account,
//     and not used: those tokens are for their own programs too.

// Checked says how a sign-in was checked.
const (
	// CheckedByProvider is a sign-in the provider answered for.
	CheckedByProvider = "provider"
	// CheckedSignInFile is a sign-in file read for its account, not used.
	CheckedSignInFile = "sign_in_file"
	// CheckedNotHere is a sign-in the Identity Agent does not use itself.
	CheckedNotHere = "not_here"
)

// CheckResult is what checking a sign-in found. It never holds the secret.
type CheckResult struct {
	OK bool `json:"ok"`
	// Account is who the provider or the sign-in says it is, where it says.
	Account string `json:"account"`
	// Checked is how: CheckedByProvider, CheckedSignInFile or CheckedNotHere.
	Checked string `json:"checked"`
	// Why says, in plain words, why it is not OK, or anything to know when it is.
	Why string `json:"why,omitempty"`
}

// Sender sends one request through the Identity Agent's governed way out.
type Sender func(ctx context.Context, req *http.Request) (*http.Response, error)

// Checker checks sign-ins. The provider addresses are fields so a test can
// stand a provider up locally.
type Checker struct {
	Send Sender
	// Base addresses, without a trailing slash.
	Anthropic, OpenAI, XAI, OpenRouter, Google string
}

// NewChecker is a checker of the real providers, sending through send.
func NewChecker(send Sender) Checker {
	return Checker{Send: send,
		Anthropic: "https://api.anthropic.com", OpenAI: "https://api.openai.com",
		XAI: "https://api.x.ai", OpenRouter: "https://openrouter.ai/api", Google: "https://generativelanguage.googleapis.com"}
}

// CheckTimeout bounds one check.
const CheckTimeout = 15 * time.Second

// Check makes the one request that says whether r works. r must already have
// passed Record.Check.
func (c Checker) Check(ctx context.Context, r Record) CheckResult {
	switch {
	case r.Kind == KindSubscription && r.Provider == ClaudeCode:
		return CheckResult{Checked: CheckedNotHere, Why: "A Claude subscription is checked by Claude Code on the " +
			"computer that signed it in. The Identity Agent never uses it itself."}
	case r.Kind == KindSubscription:
		f, err := ReadSignInFile(r.Provider, r.Secret)
		if err != nil {
			return CheckResult{Checked: CheckedSignInFile, Why: err.Error()}
		}
		return CheckResult{OK: true, Checked: CheckedSignInFile, Account: f.Account}
	}
	ctx, cancel := context.WithTimeout(ctx, CheckTimeout)
	defer cancel()
	var (
		u      string
		header = http.Header{}
		name   = providerName(r.Provider)
	)
	switch r.Provider {
	case Anthropic:
		u = c.Anthropic + "/v1/models?limit=1"
		header.Set("x-api-key", r.Secret)
		header.Set("anthropic-version", "2023-06-01")
	case OpenAI:
		u = c.OpenAI + "/v1/models"
		header.Set("Authorization", "Bearer "+r.Secret)
	case XAI:
		u = c.XAI + "/v1/api-key"
		header.Set("Authorization", "Bearer "+r.Secret)
	case OpenRouter:
		u = c.OpenRouter + "/v1/key"
		header.Set("Authorization", "Bearer "+r.Secret)
	case Google:
		u = c.Google + "/v1beta/models?pageSize=1"
		header.Set("x-goog-api-key", r.Secret)
	case Local, OpenAICompatible:
		base := strings.TrimRight(strings.TrimSpace(r.Endpoint), "/")
		p, err := url.Parse(base)
		if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
			return CheckResult{Checked: CheckedByProvider, Why: "The server's address must start with http:// or https://."}
		}
		// A server that speaks Claude's format is given without /v1; one
		// that speaks OpenAI's usually ends in it.
		if r.Provider == Local || !strings.HasSuffix(base, "/v1") {
			base += "/v1"
		}
		u = base + "/models"
		if r.Secret != "" {
			header.Set("Authorization", "Bearer "+r.Secret)
			if r.Provider == Local {
				header.Set("x-api-key", r.Secret)
			}
		}
	default:
		return CheckResult{Checked: CheckedByProvider, Why: fmt.Sprintf("There is no check for %s.", r.Provider)}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return CheckResult{Checked: CheckedByProvider, Why: "The address could not be used."}
	}
	req.Header = header
	resp, err := c.Send(ctx, req)
	if err != nil {
		why := fmt.Sprintf("The Identity Agent could not reach %s.", name)
		if r.Kind == KindLocal {
			why = "The Identity Agent could not reach the server at " + r.Endpoint + ". If only the machines the " +
				"agent runs on can reach it, that may be fine: they will use it there."
		}
		return CheckResult{Checked: CheckedByProvider, Why: why}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return CheckResult{Checked: CheckedByProvider, Why: fmt.Sprintf("%s did not accept this key.", upper(name))}
	case resp.StatusCode == http.StatusTooManyRequests:
		return CheckResult{OK: true, Checked: CheckedByProvider, Account: accountFrom(r.Provider, resp, body),
			Why: fmt.Sprintf("%s accepted the key, but is limiting it right now.", upper(name))}
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return CheckResult{Checked: CheckedByProvider, Why: fmt.Sprintf("%s sent the check somewhere else (%d), "+
			"so the key was not sent on. Check the address.", upper(name), resp.StatusCode)}
	case resp.StatusCode != http.StatusOK:
		return CheckResult{Checked: CheckedByProvider, Why: fmt.Sprintf("%s answered %d, not yes.", upper(name), resp.StatusCode)}
	}
	if r.Provider == XAI {
		var k struct {
			Blocked  bool `json:"api_key_blocked"`
			Disabled bool `json:"api_key_disabled"`
		}
		if json.Unmarshal(body, &k) == nil && (k.Blocked || k.Disabled) {
			return CheckResult{Checked: CheckedByProvider, Why: "xAI says this key is blocked or turned off."}
		}
	}
	return CheckResult{OK: true, Checked: CheckedByProvider, Account: accountFrom(r.Provider, resp, body)}
}

// accountFrom is what the provider says the key is: its name, or the
// organisation it belongs to.
func accountFrom(provider string, resp *http.Response, body []byte) string {
	switch provider {
	case XAI:
		var k struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(body, &k)
		return k.Name
	case OpenRouter:
		var k struct {
			Data struct {
				Label string `json:"label"`
			} `json:"data"`
		}
		_ = json.Unmarshal(body, &k)
		return k.Data.Label
	case OpenAI:
		return resp.Header.Get("openai-organization")
	}
	return ""
}

func providerName(p string) string {
	switch p {
	case Anthropic:
		return "Anthropic"
	case OpenAI:
		return "OpenAI"
	case XAI:
		return "xAI"
	case OpenRouter:
		return "OpenRouter"
	case Google:
		return "Google"
	}
	return "the server"
}

func upper(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// NoRedirects is a client that never follows a redirect, so a key is sent only
// to the address it was checked at.
func NoRedirects() *http.Client {
	return &http.Client{Timeout: CheckTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}
