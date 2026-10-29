package brainsignin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"identity-agent-core/brainsignin"
)

// provider stands in for the providers' lists of models, and writes down what
// it was asked and with which key.
func provider(t *testing.T) (*httptest.Server, *[]string) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.RequestURI()+" "+r.Header.Get("Authorization")+r.Header.Get("x-api-key"))
		mu.Unlock()
		switch {
		case r.Header.Get("Authorization") == "Bearer wrong":
			rw.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/or/v1/models":
			_, _ = rw.Write([]byte(`{"data":[
				{"id":"z-ai/glm-5","name":"Z.ai: GLM 5","context_length":200000,"pricing":{"prompt":"0.0000006","completion":"0.0000022"},"supported_parameters":["tools","temperature"]},
				{"id":"anthropic/claude-haiku-4.5","name":"Anthropic: Claude Haiku 4.5\n","context_length":200000,"pricing":{"prompt":"0.000001","completion":"0.000005"},"supported_parameters":["temperature"]},
				{"id":"anthropic/claude-haiku-4.5","name":"listed twice"},
				{"id":"","name":"no id"},
				{"id":"odd/pricing","name":"Odd","context_length":"8192","pricing":{"prompt":"free","completion":0.5}}]}`))
		case r.URL.Path == "/a/v1/models" && r.URL.Query().Get("after_id") == "":
			_, _ = rw.Write([]byte(`{"data":[{"id":"claude-b","display_name":"Claude B"}],"has_more":true,"last_id":"claude-b"}`))
		case r.URL.Path == "/a/v1/models":
			_, _ = rw.Write([]byte(`{"data":[{"id":"claude-a","display_name":"Claude A"}],"has_more":false}`))
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func checkerOf(srv *httptest.Server) brainsignin.Checker {
	return brainsignin.Checker{Anthropic: srv.URL + "/a", OpenRouter: srv.URL + "/or",
		Send: func(ctx context.Context, req *http.Request, c *http.Client) (*http.Response, error) { return c.Do(req) }}
}

// OpenRouter's models are listed with their names, context lengths, prices
// per token and whether they can use tools, once each, sorted by name, every field one printable line; the
// key goes only to OpenRouter's own address.
func TestOpenRoutersModelsAreListedWithTheirPrices(t *testing.T) {
	srv, seen := provider(t)
	got := checkerOf(srv).Models(context.Background(), brainsignin.Record{Kind: brainsignin.KindAPIKey,
		Provider: brainsignin.OpenRouter, Secret: "sk-or-v1-key"})
	if got.Why != "" || len(got.Models) != 3 {
		t.Fatalf("the list: %+v", got)
	}
	h := got.Models[0]
	if h.ID != "anthropic/claude-haiku-4.5" || h.Name != "Anthropic: Claude Haiku 4.5" || h.ContextLength != 200000 ||
		h.PromptPrice != "0.000001" || h.CompletionPrice != "0.000005" {
		t.Fatalf("the first model: %+v", h)
	}
	if o := got.Models[1]; o.ID != "odd/pricing" || o.ContextLength != 8192 || o.PromptPrice != "" || o.CompletionPrice != "0.5" {
		t.Fatalf("a model with odd pricing: %+v", o)
	}
	// Whether each can use tools, where OpenRouter says; nothing where it does not.
	if g := got.Models[2]; g.UsesTools == nil || !*g.UsesTools {
		t.Fatalf("a model that uses tools: %+v", g)
	}
	if h.UsesTools == nil || *h.UsesTools {
		t.Fatalf("a model that does not use tools: %+v", h)
	}
	if got.Models[1].UsesTools != nil {
		t.Fatalf("a model OpenRouter said nothing of: %+v", got.Models[1])
	}
	if len(*seen) != 1 || (*seen)[0] != "/or/v1/models Bearer sk-or-v1-key" {
		t.Fatalf("OpenRouter was asked: %v", *seen)
	}
}

// Anthropic's paged list is read to its end; a key the provider refuses, and a
// subscription, give a reason and no list.
func TestAPagedListIsReadWholeAndARefusalSaysWhy(t *testing.T) {
	srv, _ := provider(t)
	c := checkerOf(srv)
	got := c.Models(context.Background(), brainsignin.Record{Kind: brainsignin.KindAPIKey, Provider: brainsignin.Anthropic, Secret: "sk-ant-key"})
	if len(got.Models) != 2 || got.Models[0].ID != "claude-a" || got.Models[1].Name != "Claude B" {
		t.Fatalf("Anthropic's list: %+v", got)
	}
	if got := c.Models(context.Background(), brainsignin.Record{Kind: brainsignin.KindAPIKey, Provider: brainsignin.OpenRouter,
		Secret: "wrong"}); len(got.Models) != 0 || !strings.Contains(got.Why, "did not accept this key") {
		t.Fatalf("a refused key: %+v", got)
	}
	if got := c.Models(context.Background(), brainsignin.Record{Kind: brainsignin.KindSubscription, Provider: brainsignin.Grok,
		Secret: "{}"}); len(got.Models) != 0 || got.Why == "" {
		t.Fatalf("a subscription: %+v", got)
	}
}

// A model server is never asked for its list: its address is the caller's,
// and nothing such a server answers is passed back.
func TestAModelServerIsNeverAskedForItsList(t *testing.T) {
	srv, seen := provider(t)
	for _, p := range []string{brainsignin.Local, brainsignin.OpenAICompatible} {
		got := checkerOf(srv).Models(context.Background(), brainsignin.Record{Kind: brainsignin.KindLocal,
			Provider: p, Endpoint: srv.URL})
		if len(got.Models) != 0 || got.Why == "" || len(*seen) != 0 {
			t.Fatalf("%s: a model server was asked for its list: %+v %v", p, got, *seen)
		}
	}
}
