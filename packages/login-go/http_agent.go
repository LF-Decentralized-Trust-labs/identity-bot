package login

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxAnswer = 1 << 20

// HTTPAgent reaches an Identity Agent on its public login routes,
// {URL}/api/login/session/{asset}: what a site's own back end uses.
type HTTPAgent struct {
	// URL is the Identity Agent's base address.
	URL string
	// AssetID is the asset the sign-in is on.
	AssetID string
	// Client is the HTTP client; http.DefaultClient when nil.
	Client *http.Client
}

func (h HTTPAgent) base() string { return strings.TrimSuffix(h.URL, "/") }

// escape is encodeURIComponent for one path segment.
func escape(s string) string { return strings.ReplaceAll(url.PathEscape(s), "+", "%2B") }

func (h HTTPAgent) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return http.DefaultClient
}

// Scope implements Agent.
func (h HTTPAgent) Scope() string { return h.base() + "|" + h.AssetID }

// Start implements Agent.
func (h HTTPAgent) Start(ctx context.Context, r StartRequest) (Started, error) {
	b := h.base()
	body := map[string]any{"audience": r.Audience, "requestDisclosures": r.RequestDisclosures}
	if r.BrowserKey != "" {
		body["browserKey"] = r.BrowserKey
	}
	if r.FrontEnd != "" {
		body["frontEnd"] = r.FrontEnd
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return Started{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b+"/api/login/session/"+escape(h.AssetID), bytes.NewReader(raw))
	if err != nil {
		return Started{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := h.client().Do(req)
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
	_ = json.Unmarshal(data, &out) // a body that is not JSON leaves the fields empty, which StartSession refuses
	return Started{SessionToken: out.SessionToken, PointerUrl: out.Pointer, CollectorSecret: out.CollectorSecret}, nil
}

// Status implements Agent.
func (h HTTPAgent) Status(ctx context.Context, sessionToken, collectorSecret string) (Status, error) {
	b := h.base()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b+"/api/login/session/"+escape(h.AssetID)+"/"+escape(sessionToken), nil)
	if err != nil {
		return Status{}, err
	}
	req.Header.Set("Accept", "application/json")
	if collectorSecret != "" {
		req.Header.Set("X-Collector-Secret", collectorSecret)
	}
	resp, err := h.client().Do(req)
	if err != nil {
		return Status{}, fmt.Errorf("login: the Identity Agent at %s could not be reached: %w", b, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Status{State: "pending"}, nil
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
		return Status{State: "pending"}, nil
	}
	st := Status{State: body.State, AppSessionToken: body.AppSessionToken, Disclosures: body.Disclosures, Reason: body.Reason,
		BrowserKey: body.BrowserKey, FrontEnd: body.FrontEnd, IdentityWithheld: body.IdentityWithheld}
	if body.MemberInfo != nil {
		st.MemberInfo = &MemberInfo{Role: body.MemberInfo.Role, DisplayName: body.MemberInfo.DisplayName}
	}
	return st, nil
}
