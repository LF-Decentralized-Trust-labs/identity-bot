package aiagents

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"identity-agent-core/permission"
	"identity-agent-core/server"
)

// An AI agent's grant, where the identity's key is held on another device.

// keyHeldElsewhere is an Identity Agent whose identity's key is held on another
// device: it publishes the same key and can no longer derive it. seed is that
// other device's key. earlier are AI agents made while the key was here, whose
// grants are gone, as before every AI agent was given one: by name, their ids.
type keyHeldElsewhere struct {
	s       *server.CoreServer
	seed    []byte
	earlier map[string]string
}

// keyElsewhereWithAIAgents is keyElsewhere, with AI agents made while the key
// was here, whose grants are gone, as before every AI agent was given one.
func keyElsewhereWithAIAgents(t *testing.T, earlier ...string) *keyHeldElsewhere {
	t.Helper()
	w := newTalkWorld(t)
	helpers.ResetSeenSignatures(t)
	helpers.WithOwnerSecret(w.s, helpers.TestOwnerSecret())
	made := map[string]string{}
	for _, name := range earlier {
		rec := httptest.NewRecorder()
		hostOf(w.s).Router().ServeHTTP(rec, helpers.Local("POST", "/api/mcp/agents", `{"name":"`+name+`","capabilities":["`+capabilityMessageAgent+`"]}`))
		var out map[string]interface{}
		json.Unmarshal(rec.Body.Bytes(), &out)
		id, _ := out["asset_id"].(string)
		if id == "" {
			t.Fatalf("provisioning %s: %d %s", name, rec.Code, rec.Body.String())
		}
		a, _ := hostOf(w.s).AssetHandler().Store.GetAsset(id)
		helpers.RecordDB(t, w.s).Exec(`DELETE FROM credentials WHERE holder_aid = ?`, a.PairwiseAID)
		mcpTokensMu.Lock()
		toks := of(w.s).loadMCPTokens()
		for i := range toks {
			if toks[i].AssetID == id {
				toks[i].GrantSAID = ""
			}
		}
		of(w.s).saveMCPTokens(toks)
		mcpTokensMu.Unlock()
		made[name] = id
	}
	return &keyHeldElsewhere{s: w.s, seed: helpers.MoveTheKeyAway(t, w.s), earlier: made}
}

// An AI agent created where the key is elsewhere may do nothing until the
// device signs its grant, and then may do what it was granted.
func TestAnAIAgentIsGrantedOnceTheDeviceWithTheKeySigns(t *testing.T) {
	e := keyElsewhereWithAIAgents(t, "Waiting")
	id := e.earlier["Waiting"]
	if rec := e.setCapabilities(t, id, capabilityMessageAgent); rec.Code != http.StatusOK {
		t.Fatalf("approving: %d %s", rec.Code, rec.Body.String())
	}
	scopes := func() []string {
		for _, tok := range of(e.s).loadMCPTokens() {
			if tok.AssetID == id {
				cc := permission.CallerContext{Scopes: tok.Scopes}
				of(e.s).applyGrantScopes(tok, &cc)
				return cc.Scopes
			}
		}
		return nil
	}
	if len(scopes()) != 0 {
		t.Fatal("an AI agent waiting for its grant may do something")
	}
	reqs := helpers.Waiting(t, e.s)
	if len(reqs) != 1 {
		t.Fatalf("%d grants were asked for", len(reqs))
	}
	if shown, err := helpers.CheckAsTheDevice(t, e.s, reqs[0]); err != nil || shown["kind"] != "ai_agent" {
		t.Fatalf("the device's check: %v %v", shown, err)
	}
	if rec := helpers.Fulfil(t, e.s, reqs[0], e.seed); rec.Code != http.StatusOK {
		t.Fatalf("the device's signature: %d %s", rec.Code, rec.Body.String())
	}
	if len(scopes()) == 0 {
		t.Fatal("the AI agent may still do nothing once its grant is signed")
	}
	helpers.KeyLogVerifies(t, e.s)
}

// At most one grant waits for an AI agent: asking again withdraws the one
// waiting, and an agent changed underneath is not granted what it was.
func TestOnlyTheNewestGrantWaitsForAnAIAgent(t *testing.T) {
	e := keyElsewhereWithAIAgents(t, "Changing")
	id := e.earlier["Changing"]
	if rec := e.setCapabilities(t, id, capabilityMessageAgent); rec.Code != http.StatusOK {
		t.Fatalf("approving: %d %s", rec.Code, rec.Body.String())
	}
	first := helpers.Waiting(t, e.s)
	if rec := e.setCapabilities(t, id, capabilityMessageAgent, "system.info.read"); rec.Code != http.StatusOK {
		t.Fatalf("changing: %d %s", rec.Code, rec.Body.String())
	}
	now := helpers.Waiting(t, e.s)
	if len(first) != 1 || len(now) != 1 || now[0].ID == first[0].ID {
		t.Fatalf("waiting before %d, after %d", len(first), len(now))
	}
	if rec := helpers.Fulfil(t, e.s, first[0], e.seed); !strings.Contains(rec.Body.String(), `"in_force":false`) {
		t.Fatalf("signing the withdrawn grant was answered %d %s", rec.Code, rec.Body.String())
	}
	if held, _ := hostOf(e.s).AssetHandler().Store.GetAsset(id); hostOf(e.s).FindCapabilityGrant(held.PairwiseAID) != nil {
		t.Fatal("the withdrawn grant is in force")
	}
	// Taken up at the place the newer grant was built for, which is built
	// again behind the withdrawal.
	helpers.WithdrawWith(t, e.s, e.seed)
	now = helpers.Waiting(t, e.s)
	// Changed underneath, in its files, after the grant was asked for.
	a, _ := hostOf(e.s).AssetHandler().Store.GetAsset(id)
	a.Capabilities = []string{capabilityMessageAgent}
	hostOf(e.s).AssetHandler().Store.UpsertAsset(a)
	if rec := helpers.Fulfil(t, e.s, now[0], e.seed); rec.Code < 400 {
		t.Fatalf("signing a grant for an AI agent changed since was answered %d", rec.Code)
	}
	if hostOf(e.s).FindCapabilityGrant(a.PairwiseAID) != nil {
		t.Fatal("an AI agent changed since was granted what it was")
	}
	helpers.WithdrawWith(t, e.s, e.seed)
	helpers.KeyLogVerifies(t, e.s)
}

// Where the key is elsewhere, an earlier AI agent approved by its owner
// waits for the device rather than failing; one already granted is refused
// before anything is asked for, since its grant could not be withdrawn here.
func TestApprovingWhereTheKeyIsElsewhereWaitsOrRefuses(t *testing.T) {
	w := newTalkWorld(t)
	helpers.ResetSeenSignatures(t)
	provision := func(name string) string {
		rec := httptest.NewRecorder()
		hostOf(w.s).Router().ServeHTTP(rec, helpers.Local("POST", "/api/mcp/agents", `{"name":"`+name+`","capabilities":["`+capabilityMessageAgent+`"]}`))
		var made map[string]interface{}
		json.Unmarshal(rec.Body.Bytes(), &made)
		id, _ := made["asset_id"].(string)
		if id == "" {
			t.Fatalf("provisioning %s: %d %s", name, rec.Code, rec.Body.String())
		}
		return id
	}
	earlier, granted := provision("Earlier"), provision("Granted")
	ea, _ := hostOf(w.s).AssetHandler().Store.GetAsset(earlier)
	helpers.RecordDB(t, w.s).Exec(`DELETE FROM credentials WHERE holder_aid = ?`, ea.PairwiseAID)
	mcpTokensMu.Lock()
	toks := of(w.s).loadMCPTokens()
	for i := range toks {
		if toks[i].AssetID == earlier {
			toks[i].GrantSAID = ""
		}
	}
	of(w.s).saveMCPTokens(toks)
	mcpTokensMu.Unlock()
	owner, _ := w.s.DataStore.GetIdentity()
	owner.DerivationIndex += 1000
	w.s.DataStore.SaveIdentity(*owner)
	e := &keyHeldElsewhere{s: w.s}
	if rec := e.setCapabilities(t, earlier, capabilityMessageAgent); rec.Code != http.StatusOK {
		t.Fatalf("approving an earlier AI agent where the key is elsewhere: %d %s", rec.Code, rec.Body.String())
	}
	if !of(w.s).agentGrantPendingFor(earlier) || len(helpers.Waiting(t, w.s)) != 1 {
		t.Fatal("the approved AI agent is not waiting for the device")
	}
	if rec := e.setCapabilities(t, granted, capabilityMessageAgent); rec.Code != http.StatusConflict {
		t.Fatalf("re-granting an AI agent already granted, where the key is elsewhere, was answered %d", rec.Code)
	}
	if len(helpers.Waiting(t, w.s)) != 1 {
		t.Fatal("a grant was asked for before re-granting was refused")
	}
}

// An AI agent is not made where the identity's key is on another device: its
// identity is approved by an interaction only that key may sign, and nothing
// is written into the key log unsigned.
func TestAnAIAgentIsNotMadeWhereTheKeyIsElsewhere(t *testing.T) {
	e := keyElsewhereWithAIAgents(t)
	owner, _ := e.s.DataStore.GetIdentity()
	before, _ := e.s.DataStore.GetEvents(owner.AID)
	rec := httptest.NewRecorder()
	hostOf(e.s).Router().ServeHTTP(rec, helpers.SignedFor(t, hostOf(e.s).ThisIdentityAgentsIdentifier(), "POST", "/api/mcp/agents", `{"name":"Here","capabilities":["`+capabilityMessageAgent+`"]}`, helpers.TestOwnerSeed(), time.Now()))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "another device") {
		t.Fatalf("making an AI agent where the key is elsewhere was answered %d %s", rec.Code, rec.Body.String())
	}
	if after, _ := e.s.DataStore.GetEvents(owner.AID); len(after) != len(before) {
		t.Fatal("an event was written into the key log")
	}
	for _, ev := range before {
		if ev.CesrSignature == "" {
			t.Fatalf("event %d of the key log is unsigned", ev.SequenceNumber)
		}
	}
}

// A key held here that cannot be read right now is not a key held elsewhere:
// it is reported as unavailable, nothing is asked of a device that does not
// exist, and the stored seed is never replaced.
func TestAnUnreadableKeyIsNotAKeyElsewhere(t *testing.T) {
	w := newTalkWorld(t)
	helpers.ResetSeenSignatures(t)
	path := filepath.Join(w.s.DataDir, "secureenclave", "root_seed.key")
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o600) })
	if err := hostOf(w.s).KeyCanSign(); !errors.Is(err, helpers.ErrKeyUnavailable()) {
		t.Fatalf("an unreadable key reads as %v", err)
	}
	if hostOf(w.s).KeyIsElsewhere() {
		t.Fatal("an unreadable key reads as held elsewhere")
	}
	g := helpers.GrantFor(5, server.GradeEnrolled)
	body := `{"controller_aid":"` + g.ControllerAID + `","public_key":"` + g.PublicKey + `","label":"` + g.Label + `","grade":"` + string(g.Grade) + `"}`
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, helpers.SignedFor(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), "POST", "/api/controllers", body, helpers.TestOwnerSeed(), time.Now()))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("granting with the key unreadable was answered %d %s", rec.Code, rec.Body.String())
	}
	if len(helpers.Waiting(t, w.s)) != 0 {
		t.Fatal("a grant was asked of another device, where there is none")
	}
	if got, _, _ := helpers.ControllerRow(w.s, g.ControllerAID); got.CredentialPending {
		t.Fatal("the machine was marked as waiting for another device")
	}
	rec = httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, helpers.SignedFor(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), "POST", "/api/mcp/agents", `{"name":"Later","capabilities":["`+capabilityMessageAgent+`"]}`, helpers.TestOwnerSeed(), time.Now().Add(time.Second)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("making an AI agent with the key unreadable was answered %d %s", rec.Code, rec.Body.String())
	}
	os.Chmod(path, 0o600)
	if err := hostOf(w.s).KeyCanSign(); err != nil {
		t.Fatalf("once readable again, the stored seed is not the one it was: %v", err)
	}
}

// setCapabilities asks, signed by the owner, for an AI agent's capabilities.
func (e *keyHeldElsewhere) setCapabilities(t *testing.T, id string, caps ...string) *httptest.ResponseRecorder {
	t.Helper()
	list, _ := json.Marshal(caps)
	rec := httptest.NewRecorder()
	hostOf(e.s).Router().ServeHTTP(rec, helpers.SignedFor(t, hostOf(e.s).ThisIdentityAgentsIdentifier(), "PUT", "/api/mcp/agents/"+id+"/capabilities", `{"capabilities":`+string(list)+`}`, helpers.TestOwnerSeed(), time.Now()))
	return rec
}
