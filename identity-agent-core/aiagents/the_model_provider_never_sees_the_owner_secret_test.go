package aiagents

import (
	"net/http"
	"testing"

	"identity-agent-core/server"
)

// The owner calls the model proxy carrying the local owner secret; it must
// not travel on to the model provider, nor anything else that proves the
// caller to this agent.
func TestTheModelProviderNeverSeesWhatProvesTheCaller(t *testing.T) {
	in := http.Header{}
	in.Set(server.LocalOwnerSecretHeader, helpers.TestOwnerSecret())
	in.Set("Authorization", "Bearer x")
	in.Set("Cookie", "a=b")
	in.Set("X-IA-Token", "t")
	in.Set("Content-Type", "application/json")
	out := headersForTheModelProvider(in)
	for _, h := range []string{server.LocalOwnerSecretHeader, "Authorization", "Cookie", "X-IA-Token"} {
		if out.Get(h) != "" {
			t.Errorf("%s travelled to the model provider", h)
		}
	}
	if out.Get("Content-Type") != "application/json" {
		t.Error("the request's own headers were dropped too")
	}
}
