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
	"sort"
	"strconv"
	"strings"
	"time"
)

// invokeExternalAPI executes a registry-native external_api capability: a declarative
// mapping from validated args to one outbound HTTP call. Egress goes through
// MakeTrackedRequest: policy check, CredentialVault injection, proxy log. The caller
// never sees the provider credential.
//
// A sandboxed app reaching the same service through the proxy is authenticated the
// same way, from the same vault, matched on the same domains — so which side makes
// the call does not change what the service sees. That was not true until the proxy
// gained credential injection; this comment previously claimed a parity that did not
// exist.
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

	if rec.Egress.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(rec.Egress.TimeoutSeconds)*time.Second)
		defer cancel()
	}

	var body io.Reader
	if len(rec.Egress.BodyTemplate) > 0 {
		rendered, err := renderBodyTemplate(rec.Egress.BodyTemplate, argMap)
		if err != nil {
			return nil, fmt.Errorf("capability %q: %w", rec.ID, err)
		}
		body = bytes.NewReader(rendered)
	} else if method == http.MethodGet || method == http.MethodDelete {
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
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if len(rec.Egress.ResponseExtract) > 0 && resp.StatusCode < 400 {
		projected, err := extractResponseFields(rec.Egress.ResponseExtract, rb)
		if err != nil {
			return nil, fmt.Errorf("capability %q: %w", rec.ID, err)
		}
		rb = projected
	}
	return &InvokeResult{CapabilityID: rec.ID, Status: resp.StatusCode, Body: rb}, nil
}

var pathTokenRe = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)

var bodyTokenRe = regexp.MustCompile(`\{([a-zA-Z0-9_]+)(\|[^{}]*)?\}`)

// renderBodyTemplate fills a body template's "{name}" placeholders from args.
// Substitution happens on the decoded JSON tree, so an arg containing quotes or
// newlines can never break the document. A string that IS a single placeholder
// takes the arg's value with its JSON type preserved; placeholders embedded in a
// longer string are stringified in place. "{name|default}" falls back to the
// (string) default when the arg is absent; "{name}" without a default is
// required. Args a template never references are an error — with a template the
// placeholders are the whole arg surface.
func renderBodyTemplate(template json.RawMessage, args map[string]any) ([]byte, error) {
	var tree any
	if err := json.Unmarshal(template, &tree); err != nil {
		return nil, fmt.Errorf("invalid body template: %w", err)
	}
	used := map[string]bool{}
	var missing []string
	rendered := renderTemplateNode(tree, args, used, &missing)
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required argument(s): %s", strings.Join(missing, ", "))
	}
	var extra []string
	for k := range args {
		if !used[k] {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return nil, fmt.Errorf("unexpected argument(s): %s", strings.Join(extra, ", "))
	}
	return json.Marshal(rendered)
}

func renderTemplateNode(node any, args map[string]any, used map[string]bool, missing *[]string) any {
	switch v := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, child := range v {
			out[k] = renderTemplateNode(child, args, used, missing)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = renderTemplateNode(child, args, used, missing)
		}
		return out
	case string:
		// Whole-string placeholder: keep the arg's JSON type.
		if m := bodyTokenRe.FindStringSubmatch(v); m != nil && m[0] == v {
			name, def := m[1], m[2]
			if val, ok := args[name]; ok {
				used[name] = true
				return val
			}
			if def != "" {
				return def[1:] // strip the leading "|"
			}
			*missing = append(*missing, name)
			return v
		}
		// Embedded placeholder(s): stringify in place.
		return bodyTokenRe.ReplaceAllStringFunc(v, func(tok string) string {
			m := bodyTokenRe.FindStringSubmatch(tok)
			name, def := m[1], m[2]
			if val, ok := args[name]; ok {
				used[name] = true
				return fmt.Sprintf("%v", val)
			}
			if def != "" {
				return def[1:]
			}
			*missing = append(*missing, name)
			return tok
		})
	default:
		return node
	}
}

// extractResponseFields projects a JSON response down to the declared fields:
// output field -> dotted path ("choices.0.message.content"); a trailing "!"
// marks the path required. Optional paths that don't resolve are omitted.
func extractResponseFields(spec map[string]string, body []byte) ([]byte, error) {
	var tree any
	if err := json.Unmarshal(body, &tree); err != nil {
		return nil, fmt.Errorf("response is not JSON: %w", err)
	}
	out := map[string]any{}
	for field, path := range spec {
		required := strings.HasSuffix(path, "!")
		path = strings.TrimSuffix(path, "!")
		val, ok := lookupJSONPath(tree, path)
		if !ok {
			if required {
				return nil, fmt.Errorf("response missing expected field at %q", path)
			}
			continue
		}
		out[field] = val
	}
	return json.Marshal(out)
}

func lookupJSONPath(node any, path string) (any, bool) {
	cur := node
	for _, part := range strings.Split(path, ".") {
		switch v := cur.(type) {
		case map[string]any:
			next, ok := v[part]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(v) {
				return nil, false
			}
			cur = v[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

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
