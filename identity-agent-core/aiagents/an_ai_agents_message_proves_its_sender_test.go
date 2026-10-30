package aiagents

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/addon"
	"identity-agent-core/asset"
	"identity-agent-core/didcomm"
	"identity-agent-core/drivers"
	"identity-agent-core/keriengine"
	"identity-agent-core/store"
)

// A message to or from one of this Identity Agent's own AI agents proves its sender.

// "Own" is this Identity Agent's word that the keys are its AI agent's, and it
// takes more than files this agent writes: an asset row and a keyset can be
// written for anybody's identifier, so the identifier's key history must be
// delegated from this agent's root and approved in the root's own history.
func TestOwnIsOnlyAnAIAgentDelegatedFromHere(t *testing.T) {
	w := newTalkWorld(t)
	genuine, err := hostOf(w.s).KeySetFor(w.a.PairwiseAID)
	if err != nil {
		t.Fatal(err)
	}
	gdid, _ := genuine.DID()
	if _, err := hostOf(w.s).OwnAgentAtArrival(w.a.PairwiseAID, gdid); err != nil {
		t.Fatalf("an AI agent this Identity Agent delegated is not taken as its own: %v", err)
	}
	// Its identifier with keys it does not hold is not its own AI agent speaking.
	stranger, _ := didcomm.GenerateKeySet(w.a.PairwiseAID)
	sdid, _ := stranger.DID()
	if _, err := hostOf(w.s).OwnAgentAtArrival(w.a.PairwiseAID, sdid); err == nil || !strings.Contains(err.Error(), "not the ones") {
		t.Fatalf("keys this agent does not hold were taken as its AI agent's: %v", err)
	}

	// Somebody else's identifier, written in as if it were an AI agent here.
	const victim = "EVICTIMSOMEWHEREELSE0000000000000000000000000"
	if err := hostOf(w.s).AssetHandler().Store.UpsertAsset(asset.Asset{
		ID: "forged-asset", DisplayName: "Forged", AssetType: "ai_agent", PairwiseAID: victim,
	}); err != nil {
		t.Fatal(err)
	}
	minted, err := hostOf(w.s).KeySetFor(victim)
	if err != nil {
		t.Fatal(err)
	}
	mdid, _ := minted.DID()
	if _, err := hostOf(w.s).OwnAgentAtArrival(victim, mdid); err == nil {
		t.Fatal("a forged asset row and a minted keyset were taken as this agent's own AI agent")
	}

	// A row pointing at a key history the engine does hold, but one that no
	// delegation from the root opens: the root identity itself.
	identity, _ := w.s.DataStore.GetIdentity()
	if err := hostOf(w.s).AssetHandler().Store.UpsertAsset(asset.Asset{
		ID: "forged-root", DisplayName: identity.AID, AssetType: "ai_agent", PairwiseAID: identity.AID,
	}); err != nil {
		t.Fatal(err)
	}
	rootKeys, err := hostOf(w.s).KeySetFor(identity.AID)
	if err != nil {
		t.Fatal(err)
	}
	rootDID, _ := rootKeys.DID()
	_, err = hostOf(w.s).OwnAgentAtArrival(identity.AID, rootDID)
	if err == nil || !strings.Contains(err.Error(), "not delegated from this Identity Agent") {
		t.Fatalf("an identifier whose history is not a delegation from the root was taken as an AI agent here: %v", err)
	}

	// And a message kept as the victim's, tied as "own", proves nothing.
	jwm := &didcomm.JWM{
		ID: "forged-own", Type: didcomm.TypeNotification,
		From: "did:keri:" + victim, To: []string{"did:keri:" + identity.AID},
		CreatedTime: time.Now().UTC().Format(time.RFC3339), ExpiresTime: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Body: json.RawMessage(`{"title":"forged"}`),
	}
	rk, err := hostOf(w.s).KeySetFor(identity.AID)
	if err != nil {
		t.Fatal(err)
	}
	rdid, _ := rk.DID()
	env, err := didcomm.PackAuthcrypt(minted, rdid, jwm)
	if err != nil {
		t.Fatal(err)
	}
	_, signed, err := didcomm.UnpackAuthcryptKeeping(rk, mdid, env)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := json.Marshal(mdid)
	fixtures.RefusedFor(t, w.s, store.Notification{
		ID: jwm.ID, FromAID: victim, ToAID: identity.AID, Payload: string(jwm.Body),
		SignedMessage: base64.StdEncoding.EncodeToString(signed), SenderDID: string(keys), SenderKeyTrust: helpers.KeysOwn(),
	}, "were not tied")
}

// "Own" means an AI agent: another kind of identifier this agent holds, a
// machine or a domain, does not speak as one.
func TestOwnIsOnlyAnAIAgent(t *testing.T) {
	w := newTalkWorld(t)
	ks, _ := hostOf(w.s).KeySetFor(w.a.PairwiseAID)
	did, _ := ks.DID()
	a, ok := hostOf(w.s).AssetHandler().Store.GetAsset(w.a.ID)
	if !ok {
		t.Fatal("no asset")
	}
	a.AssetType = "domain"
	if err := hostOf(w.s).AssetHandler().Store.UpsertAsset(a); err != nil {
		t.Fatal(err)
	}
	if _, err := hostOf(w.s).OwnAgentAtArrival(w.a.PairwiseAID, did); err == nil {
		t.Fatal("an identifier that is not an AI agent was taken as one of this agent's AI agents")
	}
}

// The key history is found by identifier: renaming the AI agent does not lose
// it, and another identity held under its old name cannot stand in for it.
func TestOwnIsLookedUpByIdentifier(t *testing.T) {
	w := newTalkWorld(t)
	ks, _ := hostOf(w.s).KeySetFor(w.a.PairwiseAID)
	did, _ := ks.DID()
	a, _ := hostOf(w.s).AssetHandler().Store.GetAsset(w.a.ID)
	a.DisplayName = w.b.DisplayName
	if err := hostOf(w.s).AssetHandler().Store.UpsertAsset(a); err != nil {
		t.Fatal(err)
	}
	if _, err := hostOf(w.s).OwnAgentAtArrival(w.a.PairwiseAID, did); err != nil {
		t.Fatalf("renaming an AI agent lost its key history: %v", err)
	}
}

// Checking a message never writes: a key history the engine does not already
// hold is a refusal, not a reason to make one.
func TestCheckingOwnNeverWrites(t *testing.T) {
	w := newTalkWorld(t)
	ks, _ := hostOf(w.s).KeySetFor(w.a.PairwiseAID)
	did, _ := ks.DID()
	counting := &writeCounting{KeriEngine: w.s.KeriDriver}
	w.s.KeriDriver = counting
	if _, err := hostOf(w.s).OwnAgentAtArrival(w.a.PairwiseAID, did); err == nil {
		t.Fatal("an AI agent whose key history is not held was taken as one")
	}
	if counting.writes != 0 {
		t.Fatalf("checking an AI agent made %d identities in the engine", counting.writes)
	}
}

// A genuine message from one of this agent's own AI agents still proves itself
// after the AI agent is removed: the delegation evidence is kept with it.
func TestOwnProofOutlivesTheAIAgent(t *testing.T) {
	w := newTalkWorld(t)
	if err := fixtures.TrustLocalPeer(w.s, w.a.PairwiseAID); err != nil {
		t.Fatal(err)
	}
	from, _ := hostOf(w.s).KeySetFor(w.a.PairwiseAID)
	toKS, _ := hostOf(w.s).KeySetFor(w.b.PairwiseAID)
	to, _ := toKS.DID()
	env, err := didcomm.PackAuthcrypt(from, to, &didcomm.JWM{
		ID: "from-own-agent", Type: didcomm.TypeNotification,
		From: "did:keri:" + w.a.PairwiseAID, To: []string{"did:keri:" + w.b.PairwiseAID},
		CreatedTime: time.Now().UTC().Format(time.RFC3339), ExpiresTime: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
		Body: json.RawMessage(`{"title":"done"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(env)
	rec := httptest.NewRecorder()
	hostOf(w.s).HandleDIDCommInbound(rec, httptest.NewRequest("POST", "/didcomm", bytes.NewReader(raw)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("the message was answered %d: %s", rec.Code, rec.Body.String())
	}
	n, err := w.s.DataStore.GetNotification("from-own-agent")
	if err != nil || n == nil {
		t.Fatalf("not kept: %v", err)
	}
	if _, tie, err := hostOf(w.s).ProvedSender(*n); err != nil || tie != helpers.KeysOwn() {
		t.Fatalf("a message from this agent's own AI agent is not proved as its own: %q %v", tie, err)
	}
	if err := hostOf(w.s).AssetHandler().Store.DeleteAsset(w.a.ID); err != nil {
		t.Fatal(err)
	}
	if _, tie, err := hostOf(w.s).ProvedSender(*n); err != nil || tie != helpers.KeysOwn() {
		t.Fatalf("removing the AI agent broke a genuine old proof: %q %v", tie, err)
	}
}

// Kept delegation evidence counts only if it is about this identifier and its
// approval sits in this Identity Agent's root history, not a root of somebody
// else's making.
func TestDelegationEvidenceMustBeThisAgentsAndThisRoot(t *testing.T) {
	w := newTalkWorld(t)
	engine := w.s.KeriDriver.(drivers.KELHolder)
	evidence := func(aid string) addon.OwnEvidence {
		kel, err := engine.GetKelByAID(aid)
		if err != nil {
			t.Fatal(err)
		}
		root, err := engine.GetKelByAID(w.s.OwnerRootAID())
		if err != nil {
			t.Fatal(err)
		}
		return addon.OwnEvidence{Inception: kel.RawEventsB64[0], RootKEL: root.RawEventsB64}
	}
	if err := hostOf(w.s).DelegatedFromHere(w.a.PairwiseAID, evidence(w.a.PairwiseAID)); err != nil {
		t.Fatalf("genuine evidence was refused: %v", err)
	}
	if err := hostOf(w.s).DelegatedFromHere(w.a.PairwiseAID, evidence(w.b.PairwiseAID)); err == nil ||
		!strings.Contains(err.Error(), "is not "+w.a.PairwiseAID+"'s") {
		t.Fatalf("another AI agent's evidence was taken for this one: %v", err)
	}

	// A root and a delegate of somebody else's making, internally consistent.
	other := keriengine.New()
	s1, k1 := fixtures.SigningPair(t, 61)
	_, k2 := fixtures.SigningPair(t, 62)
	_, k3 := fixtures.SigningPair(t, 63)
	_, k4 := fixtures.SigningPair(t, 64)
	fixtures.SignsWithSeeds(other, s1)
	if _, err := other.CreateInceptionNamed(k1, k2, "elsewhere"); err != nil {
		t.Fatal(err)
	}
	d, err := other.CreateDelegatedInception(k3, k4, "their-agent", "elsewhere")
	if err != nil {
		t.Fatal(err)
	}
	dk, _ := other.GetKel("their-agent")
	rk, _ := other.GetKel("elsewhere")
	err = hostOf(w.s).DelegatedFromHere(d.AID, addon.OwnEvidence{Inception: dk.RawEventsB64[0], RootKEL: rk.RawEventsB64})
	if err == nil || !strings.Contains(err.Error(), "not this Identity Agent's") {
		t.Fatalf("a delegation from another root was taken as one from here: %v", err)
	}
}

// writeCounting is the engine with every call that makes an identity counted.
type writeCounting struct {
	drivers.KeriEngine
	writes int
}

func (e *writeCounting) GetKelByAID(string) (*drivers.DriverKelResponse, error) {
	return nil, fmt.Errorf("not held")
}

func (e *writeCounting) CreateInceptionNamed(a, b, c string) (*drivers.DriverInceptionResponse, error) {
	e.writes++
	return e.KeriEngine.CreateInceptionNamed(a, b, c)
}

func (e *writeCounting) ReinstateDelegatedIdentity(a, b, c, d string) (*drivers.DriverDelegatedInceptionResponse, error) {
	e.writes++
	return e.KeriEngine.ReinstateDelegatedIdentity(a, b, c, d)
}

func (e *writeCounting) CreateDelegatedInception(a, b, c, d string) (*drivers.DriverDelegatedInceptionResponse, error) {
	e.writes++
	return e.KeriEngine.CreateDelegatedInception(a, b, c, d)
}
