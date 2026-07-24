package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// invokeExternalAPI executes a registry-native external_api capability: a declarative
// mapping from validated args to one outbound HTTP call. Egress goes through
// MakeTrackedRequest, so the same policy check, CredentialVault injection, and proxy
// logging that govern sandbox traffic govern this call — the caller never sees the
// provider credential.
func (m *Manager) invokeExternalAPI(ctx context.Context, rec *CapabilityRecord, args []byte) (*InvokeResult, error) {
	if rec.Egress == nil || rec.Egress.BaseURL == "" {
		return nil, fmt.Errorf("capability %q has no egress mapping", rec.ID)
	}
	argMap := map[string]any{}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &argMap); err != nil {
			return nil, fmt.Errorf("capability %q: arguments must be a JSON object: %w", rec.ID, err)
		}
	}

	path, err := expandPathTemplate(rec.Egress.PathTemplate, argMap)
	if err != nil {
		return nil, fmt.Errorf("capability %q: %w", rec.ID, err)
	}

	method := strings.ToUpper(rec.Egress.Method)
	if method == "" {
		method = http.MethodGet
	}
	fullURL := strings.TrimRight(rec.Egress.BaseURL, "/") + path

	var body io.Reader
	if method == http.MethodGet || method == http.MethodDelete {
		// Remaining args become query parameters.
		if len(argMap) > 0 {
			q := url.Values{}
			for k, v := range argMap {
				q.Set(k, fmt.Sprintf("%v", v))
			}
			fullURL += "?" + q.Encode()
		}
	} else if len(argMap) > 0 {
		// Remaining args become the JSON request body.
		b, err := json.Marshal(argMap)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := m.MakeTrackedRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return &InvokeResult{CapabilityID: rec.ID, Status: resp.StatusCode, Body: rb}, nil
}

var pathTokenRe = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)

// expandPathTemplate fills "{name}" tokens from args, consuming each used arg so the
// remainder maps to query/body. A missing token is an error — never a silent literal.
func expandPathTemplate(template string, args map[string]any) (string, error) {
	var missing []string
	out := pathTokenRe.ReplaceAllStringFunc(template, func(tok string) string {
		name := tok[1 : len(tok)-1]
		v, ok := args[name]
		if !ok {
			missing = append(missing, name)
			return tok
		}
		delete(args, name)
		return url.PathEscape(fmt.Sprintf("%v", v))
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("missing required path argument(s): %s", strings.Join(missing, ", "))
	}
	return out, nil
}
