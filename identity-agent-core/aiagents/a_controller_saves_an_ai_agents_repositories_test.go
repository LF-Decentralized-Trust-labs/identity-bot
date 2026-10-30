package aiagents

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"identity-agent-core/authprovider"
)

// Whoever manages the organisation's GitHub App from the org app — its owner,
// or a machine the owner authorised — can change which repositories an AI agent
// may use, and the AI agent's grant names whoever asked.
//
// Changing an AI agent's repositories re-issues its grant, and a grant asked
// for by a signed request must rest on that request. The check of what a
// request asked for knew only the routes that set capabilities directly, so a
// grant asked for through the repositories route was refused as resting on
// nothing, and the app saw 502: from a controller always, and from the owner
// whenever they signed. Only the owner at this computer, who signs nothing,
// got through.
func TestAControllerChangesWhichRepositoriesAnAIAgentMayUse(t *testing.T) {
	w, g := githubWorld(t)
	ida := hostOf(w.s).ThisIdentityAgentsIdentifier()
	send := func(req *http.Request) (int, map[string]any, string) {
		t.Helper()
		rec := httptest.NewRecorder()
		hostOf(w.s).Router().ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out, rec.Body.String()
	}

	// Every call to GitHub a controller's request makes goes out the same way
	// the owner's does: connecting the App, which asks GitHub what it is, and
	// the list of repositories the App can reach.
	app, _ := json.Marshal(map[string]any{"app_id": 42, "installation_id": 7, "private_key": g.pem})
	code, out, raw := send(helpers.AsThatMachineTo(t, ida, w.ctlAID, "PUT", "/api/github", string(app), w.ctlSeed,
		authprovider.LevelVerified, time.Now()))
	if code != http.StatusOK || out["account"] != "acme" {
		t.Fatalf("a controller connecting the GitHub App: %d %s", code, raw)
	}
	code, out, raw = send(helpers.AsThatMachineTo(t, ida, w.ctlAID, "GET", "/api/github/repositories", "", w.ctlSeed, "", time.Time{}))
	if code != http.StatusOK {
		t.Fatalf("a controller listing the App's repositories: %d %s", code, raw)
	}
	if repos, _ := out["repositories"].([]any); len(repos) != 3 {
		t.Fatalf("a controller was not shown the App's repositories: %s", raw)
	}

	// The controller grants one repository to write and one to read, at the
	// default score, as the org app does.
	body := `{"repositories":[{"repository":"acme/docs","access":"write"},{"repository":"Acme/Site","access":"read"}]}`
	code, out, raw = send(helpers.AsThatMachineTo(t, ida, w.ctlAID, "PUT", "/api/mcp/agents/"+w.a.ID+"/github", body,
		w.ctlSeed, authprovider.LevelVerified, time.Now()))
	if code != http.StatusOK {
		t.Fatalf("a controller changing an AI agent's repositories: %d %s", code, raw)
	}
	said, _ := out["grant_said"].(string)
	if said == "" {
		t.Fatalf("no grant was issued: %s", raw)
	}
	authorisedBy(t, w, said)
	got := map[string]string{}
	for _, r := range out["repositories"].([]any) {
		m := r.(map[string]any)
		got[m["repository"].(string)] = m["access"].(string)
	}
	if want := map[string]string{"acme/docs": "write", "acme/site": "read"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("the AI agent was given %v, not %v", got, want)
	}
	// What it may do besides is kept as it was.
	a, _ := hostOf(w.s).AssetHandler().Store.GetAsset(w.a.ID)
	if !containsString(a.Capabilities, capabilityMessageAgent) {
		t.Fatalf("changing repositories dropped the AI agent's other capabilities: %v", a.Capabilities)
	}

	// Taking them away again is a request too, and rests on the same check.
	code, _, raw = send(helpers.AsThatMachineTo(t, ida, w.ctlAID, "PUT", "/api/mcp/agents/"+w.a.ID+"/github", `{"repositories":[]}`,
		w.ctlSeed, authprovider.LevelVerified, time.Now().Add(time.Second)))
	if code != http.StatusOK {
		t.Fatalf("a controller removing an AI agent's repositories: %d %s", code, raw)
	}

	// The owner, signing with the identity's key, is held to the same check.
	helpers.ResetSeenSignatures(t)
	code, out, raw = send(helpers.SignedFor(t, ida, "PUT", "/api/mcp/agents/"+w.a.ID+"/github",
		`{"repositories":[{"repository":"acme/sandbox","access":"read"}]}`, helpers.TestOwnerSeed(), time.Now()))
	if code != http.StatusOK || out["grant_said"] == "" {
		t.Fatalf("the owner's signed change of an AI agent's repositories: %d %s", code, raw)
	}
}
