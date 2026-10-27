package authorisation

import (
	"testing"
	"time"

	"identity-agent-core/schemas"
)

const reposBody = `{"repositories":[{"repository":"acme/docs","access":"write"},{"repository":"Acme/Site","access":"read"}]}`

// repoGrant is an AI agent grant issued now, giving these capabilities and
// limits, on a request.
func (w *world) repoGrant(req map[string]interface{}, about string, caps []string, limits map[string]interface{}) []byte {
	attrs := map[string]interface{}{"asset_type": "ai_agent", "name": "Research assistant", "capabilities": caps,
		"request": req, "about": about}
	if len(limits) > 0 {
		attrs["resource_constraints"] = limits
	}
	acdc, _ := w.build(schemas.AIAgentGrant.Schema.SAID, agentAID, time.Now().UTC(), attrs, w.edge())
	return acdc
}

func repoLimit(pairs ...string) map[string]interface{} {
	var names, ids []interface{}
	for i := 0; i < len(pairs); i += 2 {
		names, ids = append(names, pairs[i]), append(ids, pairs[i+1])
	}
	return map[string]interface{}{"repository": names, "repository_id": ids}
}

// What a request for repositories asked holds: write on docs, and read on
// both, whatever else the AI agent may do.
func TestARequestForRepositoriesThatHoldsPasses(t *testing.T) {
	w := newWorld(t)
	req := w.signs("PUT", "/api/mcp/agents/agent-1/github", reposBody, ago(time.Minute))
	cred := w.repoGrant(req, "agent-1", []string{"agent.message.send", "code.repository.read", "code.repository.write"},
		map[string]interface{}{
			"code.repository.read":  repoLimit("acme/docs", "101", "acme/site", "103"),
			"code.repository.write": repoLimit("acme/docs", "101"),
		})
	if err := w.check(cred); err != nil {
		t.Fatalf("a request for repositories that holds was refused: %v", err)
	}
	none := w.signs("PUT", "/api/mcp/agents/agent-1/github", `{"repositories":[]}`, ago(time.Minute))
	if err := w.check(w.repoGrant(none, "agent-1", []string{"agent.message.send"}, nil)); err != nil {
		t.Fatalf("a request for no repositories that holds was refused: %v", err)
	}
}

// A grant that gives other repositories, other access, or another AI agent
// than the request asked for does not rest on it.
func TestARepositoryGrantMustBeWhatWasAskedFor(t *testing.T) {
	w := newWorld(t)
	read := repoLimit("acme/docs", "101", "acme/site", "103")
	write := repoLimit("acme/docs", "101")
	both := []string{"code.repository.read", "code.repository.write"}
	cases := map[string][]byte{
		"a repository not asked for": w.repoGrant(w.signs("PUT", "/api/mcp/agents/agent-1/github", reposBody, ago(time.Minute)), "agent-1", both,
			map[string]interface{}{"code.repository.read": repoLimit("acme/docs", "101", "acme/site", "103", "acme/secret", "104"), "code.repository.write": write}),
		"write where only read was asked": w.repoGrant(w.signs("PUT", "/api/mcp/agents/agent-1/github", reposBody, ago(time.Minute)), "agent-1", both,
			map[string]interface{}{"code.repository.read": read, "code.repository.write": repoLimit("acme/docs", "101", "acme/site", "103")}),
		"a repository asked for left out": w.repoGrant(w.signs("PUT", "/api/mcp/agents/agent-1/github", reposBody, ago(time.Minute)), "agent-1",
			[]string{"code.repository.read"}, map[string]interface{}{"code.repository.read": read}),
		"a repository without its number": w.repoGrant(w.signs("PUT", "/api/mcp/agents/agent-1/github", reposBody, ago(time.Minute)), "agent-1", both,
			map[string]interface{}{"code.repository.read": map[string]interface{}{"repository": []interface{}{"acme/docs", "acme/site"}, "repository_id": []interface{}{"101"}}, "code.repository.write": write}),
		"one number for two repositories": w.repoGrant(w.signs("PUT", "/api/mcp/agents/agent-1/github", reposBody, ago(time.Minute)), "agent-1", both,
			map[string]interface{}{"code.repository.read": repoLimit("acme/docs", "101", "acme/site", "101"), "code.repository.write": write}),
		"another AI agent": w.repoGrant(w.signs("PUT", "/api/mcp/agents/agent-1/github", reposBody, ago(time.Minute)), "agent-2", both,
			map[string]interface{}{"code.repository.read": read, "code.repository.write": write}),
		"repositories when none were asked": w.repoGrant(w.signs("PUT", "/api/mcp/agents/agent-1/github", `{"repositories":[]}`, ago(time.Minute)), "agent-1",
			[]string{"code.repository.read"}, map[string]interface{}{"code.repository.read": read}),
	}
	// Whatever else a client puts beside a repository is not kept.
	if asked, _ := Asked(`{"repositories":[{"repository":"acme/docs","access":"read","note":"private"}]}`); string(asked["repositories"]) != `[{"repository":"acme/docs","access":"read"}]` {
		t.Errorf("a request's repositories are kept with more than was asked: %s", asked["repositories"])
	}
	for name, cred := range cases {
		// Each was built on the body it was signed over; check against that one.
		if name == "repositories when none were asked" {
			w.body = `{"repositories":[]}`
		} else {
			w.body = reposBody
		}
		if err := w.check(cred); err == nil {
			t.Errorf("a grant giving %s was accepted", name)
		}
	}
}
