package server

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/authprovider"
	"identity-agent-core/brainsignin"
	"identity-agent-core/sandbox"
	"identity-agent-core/vault"
)

// signInWorld is the talk world with an unlocked vault, and the owner at this
// computer.
func signInWorld(t *testing.T) *talkWorld {
	t.Helper()
	w := newTalkWorld(t)
	w.s.localOwnerSecret = testOwnerSecret
	key := bytes.Repeat([]byte{7}, 32)
	w.s.Vault.SetKeyProvider(func() ([]byte, error) { return key, nil })
	return w
}

func (w *talkWorld) asOwner(t *testing.T, method, path, body string) (int, map[string]any, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, local(method, path, body))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

// noFileHolds fails if any file under dir holds secret as it was typed.
func noFileHolds(t *testing.T, dir, secret string) {
	t.Helper()
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil && bytes.Contains(b, []byte(secret)) {
			t.Errorf("%s holds the secret as it was typed", p)
		}
		return nil
	})
}

func governanceRows(t *testing.T, w *talkWorld, event string) []sandbox.InvocationEvent {
	t.Helper()
	rows, err := w.s.SandboxManager.Store().QueryInvocationEvents(sandbox.InvocationEventFilter{CapabilityID: event})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// A key typed where the brain's reference belongs is kept in the vault and
// nowhere else: the AI agent's record names the vault entry, and nothing that
// shows an AI agent returns the key. Before, the key was stored on the record
// as typed and returned in every view of the AI agent.
func TestAKeySentAsTheBrainsReferenceIsKeptOnlyInTheVault(t *testing.T) {
	w := signInWorld(t)
	const key = "sk-ant-api03-THE-ORGANISATIONS-OWN-KEY"
	code, out, raw := w.asOwner(t, "POST", "/api/mcp/agents", `{"name":"Writer","capabilities":["`+
		capabilityMessageAgent+`"],"brain":{"kind":"remote","provider":"Anthropic","model":"claude-sonnet-4-5","credential_ref":"`+key+`"}}`)
	if code != http.StatusCreated {
		t.Fatalf("creating: %d %s", code, raw)
	}
	if strings.Contains(raw, key) {
		t.Fatal("the answer to creating the AI agent returned the key")
	}
	id := out["asset_id"].(string)
	a, _ := w.s.assetHandler.Store.GetAsset(id)
	if got := a.AgentConfig.Brain; got.CredentialRef != vault.BrainSignInRef(id) || got.Provider != brainsignin.Anthropic ||
		got.Kind != brainsignin.KindAPIKey {
		t.Fatalf("the brain does not name its sign-in, normalised: %+v", got)
	}
	rec, had, err := (signInVault{w.s.Vault}).BrainSignIn(vault.BrainSignInRef(id))
	if err != nil || !had || rec.Secret != key || rec.Provider != brainsignin.Anthropic || rec.MaxConcurrentRuns != 0 {
		t.Fatalf("the vault does not hold the key as a sign-in: %+v %v %v", rec.Public(), had, err)
	}
	for _, path := range []string{"/api/mcp/agents", "/api/assets/", "/api/assets/" + id, "/api/mcp/agents/" + id + "/brain-sign-in"} {
		code, _, body := w.asOwner(t, "GET", path, "")
		if code != http.StatusOK {
			t.Fatalf("reading %s: %d %s", path, code, body)
		}
		if strings.Contains(body, key) {
			t.Fatalf("%s returned the key", path)
		}
	}
	noFileHolds(t, w.s.DataDir, key)

	// A change to the configuration that sends a key does the same.
	const second = "sk-ant-api03-A-SECOND-KEY"
	code, _, raw = w.asOwner(t, "PATCH", "/api/mcp/agents/"+id, `{"role":"writes","brain":{"kind":"remote","provider":"Anthropic","credential_ref":"`+second+`"}}`)
	if code != http.StatusOK || strings.Contains(raw, second) {
		t.Fatalf("changing the configuration: %d %s", code, raw)
	}
	if rec, _, _ := (signInVault{w.s.Vault}).BrainSignIn(vault.BrainSignInRef(id)); rec.Secret != second {
		t.Fatal("the second key is not the one kept")
	}
	// And one that does not mention the sign-in keeps it.
	if code, _, raw := w.asOwner(t, "PATCH", "/api/mcp/agents/"+id, `{"role":"edits","brain":{"kind":"api_key","provider":"anthropic"}}`); code != http.StatusOK {
		t.Fatalf("changing the role: %d %s", code, raw)
	}
	a, _ = w.s.assetHandler.Store.GetAsset(id)
	if a.AgentConfig.Brain.CredentialRef != vault.BrainSignInRef(id) {
		t.Fatal("a change that did not mention the sign-in dropped it")
	}
	noFileHolds(t, w.s.DataDir, second)
}

// A key an earlier version stored on an AI agent's record is moved into the
// vault at start, and the record keeps only the reference.
func TestAKeyStoredOnARecordMovesIntoTheVault(t *testing.T) {
	w := signInWorld(t)
	const key = "xai-AN-OLD-KEY-ON-THE-RECORD"
	a := *w.a
	a.AgentConfig = &asset.AgentConfig{Brain: asset.BrainConfig{Kind: "remote", Provider: "xAI", CredentialRef: key}}
	if err := w.s.assetHandler.Store.UpsertAsset(a); err != nil {
		t.Fatal(err)
	}
	w.s.moveBrainSecretsIntoTheVault()
	got, _ := w.s.assetHandler.Store.GetAsset(a.ID)
	if got.AgentConfig.Brain.CredentialRef != vault.BrainSignInRef(a.ID) {
		t.Fatalf("the record still holds what it held: %+v", got.AgentConfig.Brain)
	}
	rec, had, _ := (signInVault{w.s.Vault}).BrainSignIn(vault.BrainSignInRef(a.ID))
	if !had || rec.Secret != key || rec.Provider != brainsignin.XAI {
		t.Fatalf("the vault does not hold the moved key: %+v", rec.Public())
	}
	noFileHolds(t, w.s.DataDir, key)
}

// A request that creates an AI agent is kept as it was signed, with the grant
// it authorises, and exported with that grant. A key in it would be kept and
// exported too, so a signed request carrying one is refused and nothing is
// made; the key is sent on its own, to the sign-in route, which keeps nothing
// but the vault entry.
func TestASignedRequestToCreateAnAIAgentCarriesNoKey(t *testing.T) {
	w := signInWorld(t)
	const key = "sk-ant-api03-SENT-IN-A-SIGNED-REQUEST"
	for _, brain := range []string{
		`"brain":{"kind":"remote","provider":"anthropic","credential_ref":"` + key + `"}`,
		`"brain":{"kind":"api_key","provider":"anthropic"},"brain_sign_in":{"kind":"api_key","provider":"anthropic","secret":"` + key + `"}`,
	} {
		body := `{"name":"Signed","capabilities":["` + capabilityMessageAgent + `"],` + brain + `}`
		req := asThatMachineTo(t, w.s.thisIdentityAgentsIdentifier(), w.ctlAID, "POST", "/api/mcp/agents", body, w.ctlSeed, authprovider.LevelVerified, time.Now())
		rec := httptest.NewRecorder()
		w.s.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "brain-sign-in") {
			t.Fatalf("a signed request carrying a key: %d %s", rec.Code, rec.Body.String())
		}
	}
	for _, a := range w.s.assetHandler.ListAgents() {
		if a.DisplayName == "Signed" {
			t.Fatal("an AI agent was made from a request carrying a key")
		}
	}
	// The same machine signs the brain in on its own.
	req := asThatMachineTo(t, w.s.thisIdentityAgentsIdentifier(), w.ctlAID, "PUT", "/api/mcp/agents/"+w.a.ID+"/brain-sign-in",
		`{"kind":"api_key","provider":"anthropic","secret":"`+key+`"}`, w.ctlSeed, authprovider.LevelVerified, time.Now())
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), key) {
		t.Fatalf("a controller signing the brain in: %d %s", rec.Code, rec.Body.String())
	}
	noFileHolds(t, w.s.DataDir, key)
}

// A browser session cannot sign an AI agent's brain in or remove its sign-in:
// either outlives the session, as changing the brain's configuration does.
func TestABrowserSessionCannotChangeABrainsSignIn(t *testing.T) {
	for _, route := range []string{
		"PUT /api/mcp/agents/{id}/brain-sign-in", "DELETE /api/mcp/agents/{id}/brain-sign-in",
		// A check makes the Identity Agent reach an address the caller names.
		"POST /api/mcp/brain-sign-in/test", "POST /api/mcp/agents/{id}/brain-sign-in/test",
		"POST /api/mcp/brain-sign-in/models", "POST /api/mcp/agents/{id}/brain-sign-in/models",
		"PUT /api/mcp/agents/{id}/brain",
	} {
		if _, ok := sessionForbidden[route]; !ok {
			t.Errorf("%s is open to a browser session", route)
		}
	}
}

// With the vault locked, a configuration change carrying a key changes
// nothing, rather than storing the brain without its key.
func TestALockedVaultChangesNothing(t *testing.T) {
	w := newTalkWorld(t)
	w.s.localOwnerSecret = testOwnerSecret
	before, _ := w.s.assetHandler.Store.GetAsset(w.a.ID)
	code, _, raw := w.asOwner(t, "PATCH", "/api/mcp/agents/"+w.a.ID,
		`{"role":"changed","brain":{"kind":"remote","provider":"anthropic","credential_ref":"sk-ant-api03-LOCKED"}}`)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("a key with the vault locked: %d %s", code, raw)
	}
	after, _ := w.s.assetHandler.Store.GetAsset(w.a.ID)
	if after.AgentConfig.Role != before.AgentConfig.Role {
		t.Fatal("the configuration changed though the key could not be kept")
	}
	noFileHolds(t, w.s.DataDir, "sk-ant-api03-LOCKED")
}
