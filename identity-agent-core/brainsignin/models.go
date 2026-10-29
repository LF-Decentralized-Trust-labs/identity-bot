package brainsignin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Listing the models a provider offers a key — for OpenRouter, its whole
// catalogue — so a person chooses one rather than typing its name.
//
// It is the same kind of question a check asks — which models may this key
// use — sent the same way: one key, the provider's own address, no redirect,
// nothing of anybody's words. Only the providers this Identity Agent knows the
// address of are asked. A model server's address is the caller's, and nothing
// such a server answers is passed back (ADR-052), so its model is named, not
// chosen from a list. A subscription is not asked: its token is for its own
// program, which chooses among its own models.

// Model is one model a provider offers. Prices are per token, in the
// provider's currency, as the provider states them; empty where it does not.
type Model struct {
	ID              string `json:"id"`
	Name            string `json:"name,omitempty"`
	ContextLength   int    `json:"context_length,omitempty"`
	PromptPrice     string `json:"prompt_price,omitempty"`
	CompletionPrice string `json:"completion_price,omitempty"`
}

// ModelsResult is what listing a sign-in's models found. It never holds the
// secret, and its reason is a fixed sentence: nothing the provider answered
// but the list is passed back.
type ModelsResult struct {
	Models []Model `json:"models"`
	Why    string  `json:"why,omitempty"`
}

const (
	// modelsListed bounds how many models one list holds.
	modelsListed = 5000
	// modelsAnswerLargest bounds one page of a provider's list.
	modelsAnswerLargest = 16 << 20
	// modelsPages bounds how many pages of a paged list are read.
	modelsPages = 20
)

// Models lists the models r may call. r must already have passed Record.Check.
func (c Checker) Models(ctx context.Context, r Record) ModelsResult {
	if r.Kind == KindSubscription {
		return ModelsResult{Why: "A subscription's own program chooses among its models; there is no list to choose from here."}
	}
	ctx, cancel := context.WithTimeout(ctx, CheckTimeout)
	defer cancel()
	header := http.Header{}
	client := NoRedirects()
	var u string

	switch r.Provider {
	case Anthropic:
		u = c.Anthropic + "/v1/models?limit=1000"
		header.Set("x-api-key", r.Secret)
		header.Set("anthropic-version", "2023-06-01")
	case OpenAI:
		u = c.OpenAI + "/v1/models"
		header.Set("Authorization", "Bearer "+r.Secret)
	case XAI:
		u = c.XAI + "/v1/models"
		header.Set("Authorization", "Bearer "+r.Secret)
	case OpenRouter:
		u = c.OpenRouter + "/v1/models"
		header.Set("Authorization", "Bearer "+r.Secret)
	case Local, OpenAICompatible:
		return ModelsResult{Why: "A model server's models are named, not listed: the Identity Agent passes back nothing such a server answers."}
	default:
		return ModelsResult{Why: fmt.Sprintf("There is no list of models for %s.", r.Provider)}
	}
	who := upper(providerName(r.Provider))
	var all []Model
	for page := 0; page < modelsPages; page++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return ModelsResult{Why: whyBadAddress}
		}
		req.Header = header.Clone()
		resp, err := c.Send(ctx, req, client)
		if err != nil {
			return ModelsResult{Why: fmt.Sprintf("The Identity Agent could not reach %s for its models.", who)}
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, modelsAnswerLargest+1))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			return ModelsResult{Why: fmt.Sprintf("%s did not accept this key.", who)}
		case resp.StatusCode != http.StatusOK || rerr != nil:
			return ModelsResult{Why: fmt.Sprintf("%s did not give its list of models. Try again later.", who)}
		case len(body) > modelsAnswerLargest:
			return ModelsResult{Why: fmt.Sprintf("%s's list of models is larger than one may be.", who)}
		}
		models, next, ok := readModels(r.Provider, body)
		if !ok {
			return ModelsResult{Why: fmt.Sprintf("%s's list of models could not be read.", who)}
		}
		all = append(all, models...)
		if next == "" || r.Provider != Anthropic || len(all) >= modelsListed {
			break
		}
		u = c.Anthropic + "/v1/models?limit=1000&after_id=" + url.QueryEscape(next)
	}
	return ModelsResult{Models: tidyModels(all)}
}

// readModels reads one page of a provider's list, and for a paged list the
// model the next page starts after.
func readModels(provider string, body []byte) ([]Model, string, bool) {
	var page struct {
		Data []struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			DisplayName   string `json:"display_name"`
			ContextLength any    `json:"context_length"`
			Pricing       struct {
				Prompt     any `json:"prompt"`
				Completion any `json:"completion"`
			} `json:"pricing"`
		} `json:"data"`
		HasMore bool   `json:"has_more"`
		LastID  string `json:"last_id"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, "", false
	}
	var out []Model
	for _, d := range page.Data {
		m := Model{ID: d.ID, Name: firstOf(d.Name, d.DisplayName), ContextLength: number(d.ContextLength)}
		if provider == OpenRouter {
			m.PromptPrice, m.CompletionPrice = price(d.Pricing.Prompt), price(d.Pricing.Completion)
		}
		out = append(out, m)
	}
	next := ""
	if page.HasMore {
		next = page.LastID
	}
	return out, next, true
}

// tidyModels keeps the models with a usable id, once each, at most
// modelsListed of them, by name, every field one short printable line.
func tidyModels(in []Model) []Model {
	seen := map[string]bool{}
	out := []Model{}
	for _, m := range in {
		m.ID, m.Name = line(m.ID, 200), line(m.Name, 200)
		m.PromptPrice, m.CompletionPrice = line(m.PromptPrice, 40), line(m.CompletionPrice, 40)
		if m.ID == "" || seen[m.ID] || len(out) >= modelsListed {
			continue
		}
		seen[m.ID] = true
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(firstOf(out[i].Name, out[i].ID)) < strings.ToLower(firstOf(out[j].Name, out[j].ID))
	})
	return out
}

// price is a price as the provider states it, if it is a number.
func price(v any) string {
	switch p := v.(type) {
	case string:
		if _, err := strconv.ParseFloat(p, 64); err == nil {
			return p
		}
	case float64:
		return strconv.FormatFloat(p, 'f', -1, 64)
	}
	return ""
}

func number(v any) int {
	switch n := v.(type) {
	case float64:
		if n > 0 && n < 1e9 {
			return int(n)
		}
	case string:
		if i, err := strconv.Atoi(n); err == nil && i > 0 && i < 1e9 {
			return i
		}
	}
	return 0
}

// line is s as one printable line of at most n bytes.
func line(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > n {
		s = strings.ToValidUTF8(s[:n], "")
	}
	return s
}

func firstOf(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
