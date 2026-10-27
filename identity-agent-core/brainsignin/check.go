package brainsignin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
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

// Sender sends one request through the Identity Agent's governed way out, with
// client: one that follows no redirect, and for a model server, one that
// reaches only the address that was checked.
type Sender func(ctx context.Context, req *http.Request, client *http.Client) (*http.Response, error)

// Checker checks sign-ins. The provider addresses are fields so a test can
// stand a provider up locally.
type Checker struct {
	Send Sender
	// Base addresses, without a trailing slash.
	Anthropic, OpenAI, XAI, OpenRouter, Google string
	// Resolve finds a model server's addresses; nil is the system's resolver.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// AddressRule says why a model server's address is not tried; nil is
	// ModelServerAddress. A test stands its server up on this computer, which
	// the rule refuses, and so replaces it.
	AddressRule func(netip.Addr) error
}

// NewChecker is a checker of the real providers, sending through send.
func NewChecker(send Sender) Checker {
	return Checker{Send: send,
		Anthropic: "https://api.anthropic.com", OpenAI: "https://api.openai.com",
		XAI: "https://api.x.ai", OpenRouter: "https://openrouter.ai/api", Google: "https://generativelanguage.googleapis.com"}
}

// CheckTimeout bounds one check.
const CheckTimeout = 15 * time.Second

// The reasons a check gives. They are fixed sentences: nothing the server
// answered — not its status, not its words — is passed back, so the check
// cannot be used to read what is at an address.
const (
	whyBadAddress = "The server's address must start with http:// or https:// and name a server."
	whyUserInfo   = "The server's address must not carry a user name or password. Give the key on its own instead."
	whyReserved   = "The Identity Agent does not try a server on its own computer or at a reserved address, " +
		"so this was not tried. The machines the agent runs on will use it there."
	whyUnreachable = "The Identity Agent could not reach the server. If only the machines the agent runs on can " +
		"reach it, that may be fine: they will use it there."
	whyNotAccepted = "The server did not accept this key."
	whyRedirected  = "The server sent the check somewhere else, so the key was not sent on. Check the address."
	whyNotYes      = "The server did not say yes. Check the address."
)

// modelServerPath is the one question a model server is asked: which models it
// has. Whatever path or query its address carries is not used.
const modelServerPath = "/v1/models"

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
		client = NoRedirects()
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
		target, pinned, why := c.modelServer(ctx, r.Endpoint)
		if why != "" {
			return CheckResult{Checked: CheckedByProvider, Why: why}
		}
		u, client = target, pinned
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
		return CheckResult{Checked: CheckedByProvider, Why: whyBadAddress}
	}
	req.Header = header
	resp, err := c.Send(ctx, req, client)
	if err != nil {
		if r.Kind == KindLocal {
			return CheckResult{Checked: CheckedByProvider, Why: whyUnreachable}
		}
		return CheckResult{Checked: CheckedByProvider, Why: fmt.Sprintf("The Identity Agent could not reach %s.", name)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	who := upper(name)
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		if r.Kind == KindLocal {
			return CheckResult{Checked: CheckedByProvider, Why: whyNotAccepted}
		}
		return CheckResult{Checked: CheckedByProvider, Why: fmt.Sprintf("%s did not accept this key.", who)}
	case resp.StatusCode == http.StatusTooManyRequests:
		return CheckResult{OK: true, Checked: CheckedByProvider, Account: accountFrom(r.Provider, resp, body),
			Why: fmt.Sprintf("%s accepted the key, but is limiting it right now.", who)}
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		if r.Kind == KindLocal {
			return CheckResult{Checked: CheckedByProvider, Why: whyRedirected}
		}
		return CheckResult{Checked: CheckedByProvider, Why: fmt.Sprintf("%s sent the check somewhere else, "+
			"so the key was not sent on.", who)}
	case resp.StatusCode != http.StatusOK:
		if r.Kind == KindLocal {
			return CheckResult{Checked: CheckedByProvider, Why: whyNotYes}
		}
		return CheckResult{Checked: CheckedByProvider, Why: fmt.Sprintf("%s did not say yes. Try again later.", who)}
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

// modelServer is the one address a model server is checked at — its scheme
// and host, and the fixed path that asks for its models — and a client that
// reaches only the addresses that name was found to have when it was
// checked, so a name that changes its answer between the check and the call
// still reaches nowhere else. It refuses an address that carries a user name
// or password, and one any of whose addresses is this computer, a link-local
// or cloud metadata address, or otherwise reserved (ModelServerAddress).
func (c Checker) modelServer(ctx context.Context, endpoint string) (string, *http.Client, string) {
	p, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Hostname() == "" || p.Opaque != "" {
		return "", nil, whyBadAddress
	}
	if p.User != nil {
		return "", nil, whyUserInfo
	}
	host, port := p.Hostname(), p.Port()
	if port == "" {
		port = "80"
		if p.Scheme == "https" {
			port = "443"
		}
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", nil, whyBadAddress
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		resolve := c.Resolve
		if resolve == nil {
			resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
				return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			}
		}
		if addrs, err = resolve(ctx, host); err != nil || len(addrs) == 0 {
			return "", nil, whyUnreachable
		}
	}
	rule := c.AddressRule
	if rule == nil {
		rule = ModelServerAddress
	}
	for _, a := range addrs {
		if rule(a) != nil {
			return "", nil, whyReserved
		}
	}
	target := (&url.URL{Scheme: p.Scheme, Host: p.Host, Path: modelServerPath}).String()
	dialer := &net.Dialer{Timeout: CheckTimeout}
	transport := &http.Transport{
		Proxy: nil,
		// Whatever address the request names, only the ones checked are dialled.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var last error
			for _, a := range addrs {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
				if err == nil {
					return conn, nil
				}
				last = err
			}
			return nil, last
		},
		TLSHandshakeTimeout: CheckTimeout,
		DisableKeepAlives:   true,
	}
	client := &http.Client{Timeout: CheckTimeout, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return target, client, ""
}

// ErrReservedAddress is an address a model server is never checked at.
var ErrReservedAddress = errors.New("a reserved address")

// metadataAddresses are cloud providers' instance metadata services outside
// the link-local range, which hand out the machine's own credentials.
var metadataAddresses = []netip.Prefix{
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud
	netip.MustParsePrefix("168.63.129.16/32"),   // Azure
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS, over IPv6
}

// reservedRanges are never a model server's.
var reservedRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("240.0.0.0/4"), // includes 255.255.255.255
	netip.MustParsePrefix("100::/64"),    // discard
}

// nat64 carries an IPv4 address inside an IPv6 one.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// ModelServerAddress says whether a model server may be checked at a. The rule:
// a model server may be on the public internet or on a private network — a
// server on the office network is an ordinary place to run one, and only the
// owner's own app may ask for a check (a browser session may not) — but never
// on the Identity Agent's own computer, at a link-local or cloud metadata
// address, or at an unspecified, multicast or otherwise reserved one.
func ModelServerAddress(a netip.Addr) error {
	a = a.Unmap()
	if a.Is6() && nat64.Contains(a) {
		b := a.As16()
		return ModelServerAddress(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
	}
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() {
		return ErrReservedAddress
	}
	for _, list := range [][]netip.Prefix{metadataAddresses, reservedRanges} {
		for _, p := range list {
			if p.Contains(a) {
				return ErrReservedAddress
			}
		}
	}
	return nil
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
