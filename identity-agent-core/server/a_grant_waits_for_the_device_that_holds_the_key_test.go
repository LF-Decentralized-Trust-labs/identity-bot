package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	keri "github.com/grapeid/keri-go"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/login"
	"identity-agent-core/sandbox"
	"identity-agent-core/schemas"
	"identity-agent-core/store"
)

// elsewhere is an Identity Agent whose identity's key is held on another
// device: it publishes the same key and can no longer derive it. seed is that
// other device's key.
type elsewhere struct {
	w    *talkWorld
	s    *CoreServer
	seed []byte
	// earlier are AI agents made while the key was here, whose grants are
	// gone, as before every AI agent was given one: by name, their ids.
	earlier map[string]string
}

func keyElsewhere(t *testing.T, earlier ...string) *elsewhere {
	t.Helper()
	w := newTalkWorld(t)
	resetSeenSignatures(t)
	w.s.localOwnerSecret = testOwnerSecret
	made := map[string]string{}
	for _, name := range earlier {
		rec := httptest.NewRecorder()
		w.s.router.ServeHTTP(rec, local("POST", "/api/mcp/agents", `{"name":"`+name+`","capabilities":["`+capabilityMessageAgent+`"]}`))
		var out map[string]interface{}
		json.Unmarshal(rec.Body.Bytes(), &out)
		id, _ := out["asset_id"].(string)
		if id == "" {
			t.Fatalf("provisioning %s: %d %s", name, rec.Code, rec.Body.String())
		}
		a, _ := w.s.assetHandler.Store.GetAsset(id)
		recordDB(t, w.s).Exec(`DELETE FROM credentials WHERE holder_aid = ?`, a.PairwiseAID)
		mcpTokensMu.Lock()
		toks := w.s.loadMCPTokens()
		for i := range toks {
			if toks[i].AssetID == id {
				toks[i].GrantSAID = ""
			}
		}
		w.s.saveMCPTokens(toks)
		mcpTokensMu.Unlock()
		made[name] = id
	}
	seed, err := w.s.identitySigningSeed()
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := w.s.DataStore.GetIdentity()
	owner.DerivationIndex += 1000
	if err := w.s.DataStore.SaveIdentity(*owner); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.identitySigningSeed(); err == nil {
		t.Fatal("the key still reads as held here")
	}
	return &elsewhere{w: w, s: w.s, seed: seed, earlier: made}
}

// pairMachine asks, signed by the owner, for machine g to be granted.
func (e *elsewhere) pairMachine(t *testing.T, g ControllerGrant) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"controller_aid":"` + g.ControllerAID + `","public_key":"` + g.PublicKey + `","label":"` + g.Label + `","grade":"` + string(g.Grade) + `"}`
	rec := httptest.NewRecorder()
	e.s.router.ServeHTTP(rec, signedFor(t, e.s.thisIdentityAgentsIdentifier(), "POST", "/api/controllers", body, testOwnerSeed(), time.Now()))
	return rec
}

// setCapabilities asks, signed by the owner, for an AI agent's capabilities.
func (e *elsewhere) setCapabilities(t *testing.T, id string, caps ...string) *httptest.ResponseRecorder {
	t.Helper()
	list, _ := json.Marshal(caps)
	rec := httptest.NewRecorder()
	e.s.router.ServeHTTP(rec, signedFor(t, e.s.thisIdentityAgentsIdentifier(), "PUT", "/api/mcp/agents/"+id+"/capabilities", `{"capabilities":`+string(list)+`}`, testOwnerSeed(), time.Now()))
	return rec
}

// waiting is what waits for the device, of the kinds it is asked to sign.
func waiting(t *testing.T, s *CoreServer) []store.SigningRequest {
	t.Helper()
	all, err := s.DataStore.GetPendingSigningRequests()
	if err != nil {
		t.Fatal(err)
	}
	var out []store.SigningRequest
	for _, r := range all {
		if isGrantKind(r.Kind) && r.Status == SigningStatusPending {
			out = append(out, r)
		}
	}
	return out
}

func signWith(req store.SigningRequest, seed []byte) string {
	payload, _ := base64.StdEncoding.DecodeString(req.PayloadB64)
	sig, _ := login.SignString(string(payload), seed)
	return sig
}

func fulfilWith(t *testing.T, s *CoreServer, id, sig string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleFulfilSigningRequest(rec, withID(ownerRequest("POST", "/api/signing-requests/"+id+"/fulfil",
		strings.NewReader(`{"signature":"`+sig+`"}`), s), id))
	return rec
}

func fulfil(t *testing.T, s *CoreServer, req store.SigningRequest, seed []byte) *httptest.ResponseRecorder {
	t.Helper()
	return fulfilWith(t, s, req.ID, signWith(req, seed))
}

// checkAsTheDevice is what the device's own core says of a request, from
// what the queue carries for it.
func checkAsTheDevice(t *testing.T, s *CoreServer, req store.SigningRequest) (map[string]interface{}, error) {
	t.Helper()
	parts := s.queuedParts(req.ID)
	shown, err := s.whatIsToBeSigned(req.PayloadB64, parts)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(shown)
	var out map[string]interface{}
	json.Unmarshal(raw, &out)
	return out, nil
}

func keyLogVerifies(t *testing.T, s *CoreServer) {
	t.Helper()
	owner, _ := s.DataStore.GetIdentity()
	events, _ := s.DataStore.GetEvents(owner.AID)
	in := drivers.ValidateKELInput{AID: owner.AID}
	for _, ev := range events {
		raw, _ := base64.StdEncoding.DecodeString(ev.RawBytesB64)
		in.RawEvents = append(in.RawEvents, raw)
		in.CesrSignatures = append(in.CesrSignatures, ev.CesrSignature)
	}
	if res, err := drivers.ValidateKELFromBytes(in); err != nil || !res.KelVerified {
		t.Fatalf("the key log does not verify: %v %+v", err, res)
	}
}

// A machine paired where the key is elsewhere waits; the device that holds the
// key checks the grant on its own core and is shown what the credential says,
// key fingerprint included; it signs, and the machine is granted with that
// signature in a key log that verifies.
func TestAMachineIsGrantedOnceTheDeviceWithTheKeySigns(t *testing.T) {
	e := keyElsewhere(t)
	owner, _ := e.s.DataStore.GetIdentity()
	before, _ := e.s.DataStore.GetEvents(owner.AID)
	g := grantFor(5, GradeEnrolled)
	if rec := e.pairMachine(t, g); rec.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rec.Code, rec.Body.String())
	}
	if got, _, _ := e.s.controllers().Get(g.ControllerAID); !got.CredentialPending {
		t.Fatal("the machine is not waiting")
	}
	if after, _ := e.s.DataStore.GetEvents(owner.AID); len(after) != len(before) {
		t.Fatal("an event was written before the device signed")
	}
	reqs := waiting(t, e.s)
	if len(reqs) != 1 || reqs[0].Presentation != PresentationConsent {
		t.Fatalf("what the device is asked: %+v", reqs)
	}
	shown, err := checkAsTheDevice(t, e.s, reqs[0])
	if err != nil {
		t.Fatalf("the device's check: %v", err)
	}
	if shown["kind"] != "machine" || shown["holder"] != g.ControllerAID || shown["public_key"] != g.PublicKey ||
		shown["key_fingerprint"] == "" || !strings.Contains(reqs[0].Summary, shown["key_fingerprint"].(string)) {
		t.Fatalf("the device is shown %v under %q", shown, reqs[0].Summary)
	}
	if rec := fulfil(t, e.s, reqs[0], e.seed); rec.Code != http.StatusOK {
		t.Fatalf("the device's signature: %d %s", rec.Code, rec.Body.String())
	}
	got, _, _ := e.s.controllers().Get(g.ControllerAID)
	if got.CredentialSAID == "" || got.CredentialPending {
		t.Fatalf("the machine is still waiting: %+v", got)
	}
	keyLogVerifies(t, e.s)
}

// An AI agent created where the key is elsewhere may do nothing until the
// device signs its grant, and then may do what it was granted.
func TestAnAIAgentIsGrantedOnceTheDeviceWithTheKeySigns(t *testing.T) {
	e := keyElsewhere(t, "Waiting")
	id := e.earlier["Waiting"]
	if rec := e.setCapabilities(t, id, capabilityMessageAgent); rec.Code != http.StatusOK {
		t.Fatalf("approving: %d %s", rec.Code, rec.Body.String())
	}
	scopes := func() []string {
		for _, tok := range e.s.loadMCPTokens() {
			if tok.AssetID == id {
				cc := sandbox.CallerContext{Scopes: tok.Scopes}
				e.s.applyGrantScopes(tok, &cc)
				return cc.Scopes
			}
		}
		return nil
	}
	if len(scopes()) != 0 {
		t.Fatal("an AI agent waiting for its grant may do something")
	}
	reqs := waiting(t, e.s)
	if len(reqs) != 1 {
		t.Fatalf("%d grants were asked for", len(reqs))
	}
	if shown, err := checkAsTheDevice(t, e.s, reqs[0]); err != nil || shown["kind"] != "ai_agent" {
		t.Fatalf("the device's check: %v %v", shown, err)
	}
	if rec := fulfil(t, e.s, reqs[0], e.seed); rec.Code != http.StatusOK {
		t.Fatalf("the device's signature: %d %s", rec.Code, rec.Body.String())
	}
	if len(scopes()) == 0 {
		t.Fatal("the AI agent may still do nothing once its grant is signed")
	}
	keyLogVerifies(t, e.s)
}

// A signature by another key changes nothing, and the request still waits.
func TestAWronglySignedGrantIsRefused(t *testing.T) {
	e := keyElsewhere(t)
	g := grantFor(5, GradeEnrolled)
	e.pairMachine(t, g)
	reqs := waiting(t, e.s)
	other := make([]byte, 32)
	other[0] = 7
	if rec := fulfil(t, e.s, reqs[0], other); rec.Code != http.StatusBadRequest {
		t.Fatalf("a signature by another key was answered %d", rec.Code)
	}
	if got, _, _ := e.s.controllers().Get(g.ControllerAID); got.CredentialSAID != "" {
		t.Fatal("a wrongly signed grant granted the machine")
	}
	if len(waiting(t, e.s)) != 1 {
		t.Fatal("the request no longer waits")
	}
}

// A grant built on a key log that has moved on is refused when signed, and
// built again for the device to sign afresh.
func TestAStaleGrantIsBuiltAgain(t *testing.T) {
	e := keyElsewhere(t)
	e.pairMachine(t, grantFor(5, GradeEnrolled))
	stale := waiting(t, e.s)[0]
	body, _, _ := e.s.DataStore.GetPendingIssuance(stale.ID)
	var p pendingIssuance
	json.Unmarshal([]byte(body), &p)
	p.Prepared.Prior = "Ethe-key-log-moved-on"
	nb, _ := json.Marshal(p)
	recordDB(t, e.s).Exec(`UPDATE pending_issuances SET body=? WHERE signing_request_id=?`, string(nb), stale.ID)
	if rec := fulfil(t, e.s, stale, e.seed); rec.Code != http.StatusConflict {
		t.Fatalf("a stale grant was answered %d %s", rec.Code, rec.Body.String())
	}
	fresh := waiting(t, e.s)
	if len(fresh) != 1 || fresh[0].ID == stale.ID {
		t.Fatalf("the stale grant was not asked for afresh: %+v", fresh)
	}
	if rec := fulfil(t, e.s, fresh[0], e.seed); rec.Code != http.StatusOK {
		t.Fatalf("the grant built again: %d %s", rec.Code, rec.Body.String())
	}
	keyLogVerifies(t, e.s)
}

// The stolen laptop: removed by the owner while its grant waits for the
// device, it is granted nothing when the device signs what it was asked.
func TestAMachineRemovedWhileItsGrantWaitsIsGrantedNothing(t *testing.T) {
	e := keyElsewhere(t)
	laptop := grantFor(5, GradeEnrolled)
	e.pairMachine(t, laptop)
	reqs := waiting(t, e.s)
	if len(reqs) != 1 {
		t.Fatalf("%d grants were asked for", len(reqs))
	}
	if err := e.s.revokeController(laptop.ControllerAID); err != nil {
		t.Fatal(err)
	}
	if len(waiting(t, e.s)) != 0 {
		t.Fatal("the removed machine's grant still waits")
	}
	// Signed all the same, it is in the device's key log: taken up here so
	// the logs agree, never in force, and withdrawn.
	if rec := fulfil(t, e.s, reqs[0], e.seed); !strings.Contains(rec.Body.String(), `"in_force":false`) {
		t.Fatalf("signing the removed machine's grant was answered %d %s", rec.Code, rec.Body.String())
	}
	if len(e.s.credentialsHeldBy(laptop.ControllerAID, schemas.ControllerGrant.Schema.SAID, e.s.OwnerRootAID(), true)) != 0 {
		t.Fatal("a grant is in force for a machine removed while it waited")
	}
	withdrawIt(t, e)
	// Removed underneath, with its request still standing, it is refused
	// when signed as well.
	again := grantFor(6, GradeEnrolled)
	e.pairMachine(t, again)
	reqs = waiting(t, e.s)
	e.s.controllers().Revoke(again.ControllerAID)
	if rec := fulfil(t, e.s, reqs[0], e.seed); rec.Code < 400 {
		t.Fatalf("signing a machine removed underneath was answered %d", rec.Code)
	}
	if got, _, _ := e.s.controllers().Get(again.ControllerAID); got.CredentialSAID != "" {
		t.Fatal("a machine removed underneath was granted")
	}
	withdrawIt(t, e)
	// Changed underneath, renamed in the file while it waited.
	changed := grantFor(7, GradeEnrolled)
	if rec := e.pairMachine(t, changed); rec.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rec.Code, rec.Body.String())
	}
	reqs = waiting(t, e.s)
	row, _, _ := e.s.controllers().Get(changed.ControllerAID)
	row.Label = "somebody else's"
	e.s.controllers().Put(row)
	if rec := fulfil(t, e.s, reqs[0], e.seed); rec.Code < 400 {
		t.Fatalf("signing a machine changed underneath was answered %d", rec.Code)
	}
	if got, _, _ := e.s.controllers().Get(changed.ControllerAID); got.CredentialSAID != "" {
		t.Fatal("a machine changed underneath was granted")
	}
	withdrawIt(t, e)
	keyLogVerifies(t, e.s)
}

// withdrawIt signs the one revocation that waits, of a grant signed and not
// wanted, and checks that grant is revoked.
func withdrawIt(t *testing.T, e *elsewhere) {
	t.Helper()
	reqs := waiting(t, e.s)
	if len(reqs) != 1 || reqs[0].Kind != signingKindRevocation {
		t.Fatalf("no withdrawal waits: %+v", reqs)
	}
	body, _, _ := e.s.DataStore.GetPendingIssuance(reqs[0].ID)
	var p pendingIssuance
	json.Unmarshal([]byte(body), &p)
	if rec := fulfil(t, e.s, reqs[0], e.seed); rec.Code != http.StatusOK {
		t.Fatalf("withdrawing: %d %s", rec.Code, rec.Body.String())
	}
	if c, _ := e.s.DataStore.GetCredential(p.Revokes); c == nil || c.Status != "revoked" {
		t.Fatalf("the grant signed and not wanted is not revoked: %+v", c)
	}
}

// At most one grant waits for an AI agent: asking again withdraws the one
// waiting, and an agent changed underneath is not granted what it was.
func TestOnlyTheNewestGrantWaitsForAnAIAgent(t *testing.T) {
	e := keyElsewhere(t, "Changing")
	id := e.earlier["Changing"]
	if rec := e.setCapabilities(t, id, capabilityMessageAgent); rec.Code != http.StatusOK {
		t.Fatalf("approving: %d %s", rec.Code, rec.Body.String())
	}
	first := waiting(t, e.s)
	if rec := e.setCapabilities(t, id, capabilityMessageAgent, "system.info.read"); rec.Code != http.StatusOK {
		t.Fatalf("changing: %d %s", rec.Code, rec.Body.String())
	}
	now := waiting(t, e.s)
	if len(first) != 1 || len(now) != 1 || now[0].ID == first[0].ID {
		t.Fatalf("waiting before %d, after %d", len(first), len(now))
	}
	if rec := fulfil(t, e.s, first[0], e.seed); !strings.Contains(rec.Body.String(), `"in_force":false`) {
		t.Fatalf("signing the withdrawn grant was answered %d %s", rec.Code, rec.Body.String())
	}
	if held, _ := e.s.assetHandler.Store.GetAsset(id); e.s.findCapabilityGrant(held.PairwiseAID) != nil {
		t.Fatal("the withdrawn grant is in force")
	}
	// Taken up at the place the newer grant was built for, which is built
	// again behind the withdrawal.
	withdrawIt(t, e)
	now = waiting(t, e.s)
	// Changed underneath, in its files, after the grant was asked for.
	a, _ := e.s.assetHandler.Store.GetAsset(id)
	a.Capabilities = []string{capabilityMessageAgent}
	e.s.assetHandler.Store.UpsertAsset(a)
	if rec := fulfil(t, e.s, now[0], e.seed); rec.Code < 400 {
		t.Fatalf("signing a grant for an AI agent changed since was answered %d", rec.Code)
	}
	if e.s.findCapabilityGrant(a.PairwiseAID) != nil {
		t.Fatal("an AI agent changed since was granted what it was")
	}
	withdrawIt(t, e)
	keyLogVerifies(t, e.s)
}

// Two signatures for one request at once: one is acted on.
func TestOneRequestIsActedOnOnce(t *testing.T) {
	e := keyElsewhere(t)
	g := grantFor(5, GradeEnrolled)
	e.pairMachine(t, g)
	req := waiting(t, e.s)[0]
	sig := signWith(req, e.seed)
	before, _ := e.s.DataStore.GetCredentials()
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = fulfilWith(t, e.s, req.ID, sig).Code
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		}
	}
	after, _ := e.s.DataStore.GetCredentials()
	if ok != 1 || len(after) != len(before)+1 {
		t.Fatalf("two signatures at once: answered %v, %d credentials issued", codes, len(after)-len(before))
	}
	if left := waiting(t, e.s); len(left) != 0 {
		t.Fatalf("the second signature asked for the grant again: %d waiting", len(left))
	}
}

// The reviewer's attack: somebody who can write the database swaps the grant
// behind a waiting request, and the payload, for a grant to their own machine,
// with or without the owner's request copied across. Nothing is issued to it.
func TestAGrantSwappedWhileItWaitsIsRefused(t *testing.T) {
	for _, copyRequest := range []bool{false, true} {
		e := keyElsewhere(t)
		g := grantFor(5, GradeEnrolled)
		e.pairMachine(t, g)
		reqs := waiting(t, e.s)
		body, _, _ := e.s.DataStore.GetPendingIssuance(reqs[0].ID)
		var p pendingIssuance
		json.Unmarshal([]byte(body), &p)
		evil := grantFor(9, GradeEnrolled)
		evil.Label = "attacker"
		claims := map[string]interface{}{"name": evil.Label, "label": evil.Label, "public_key": evil.PublicKey, "grade": string(evil.Grade),
			"i": evil.ControllerAID, "asset_type": schemas.ControllerGrant.AssetType}
		prep, err := e.s.KeriDriver.(drivers.PreparedIssuer).PrepareCredentialInRegistry(p.Spec.Issuer, claims, schemas.ControllerGrant.Schema.SAID,
			evil.ControllerAID, nil, p.Prepared.Registry)
		if err != nil {
			t.Fatal(err)
		}
		swapped := pendingIssuance{Kind: signingKindGrant, Prepared: prep,
			Spec: grantSpec{Schema: schemas.ControllerGrant.Schema.SAID, Issuer: p.Spec.Issuer, Claims: claims, Holder: evil.ControllerAID}}
		if copyRequest {
			swapped.Spec.Request, swapped.Spec.RequestDigest = p.Spec.Request, p.Spec.RequestDigest
		}
		nb, _ := json.Marshal(swapped)
		db := recordDB(t, e.s)
		db.Exec(`UPDATE pending_issuances SET body=? WHERE signing_request_id=?`, string(nb), reqs[0].ID)
		db.Exec(`UPDATE signing_requests SET payload_b64=? WHERE id=?`, base64.StdEncoding.EncodeToString(prep.IxnRaw), reqs[0].ID)
		e.s.controllers().Grant(evil, time.Now().UTC())
		reqs = waiting(t, e.s)
		if shown, err := checkAsTheDevice(t, e.s, reqs[0]); err == nil && shown["holder"] != evil.ControllerAID {
			t.Fatal("the device is shown something other than what it is asked to sign")
		}
		if rec := fulfil(t, e.s, reqs[0], e.seed); rec.Code < 400 {
			t.Fatalf("a swapped grant (request copied: %v) was answered %d", copyRequest, rec.Code)
		}
		if got, _, _ := e.s.controllers().Get(evil.ControllerAID); got.CredentialSAID != "" {
			t.Fatalf("the attacker's machine was granted (request copied: %v)", copyRequest)
		}
	}
}

// The device's check refuses a credential swapped for another behind the same
// interaction, and an interaction that does not extend its key log.
func TestTheDeviceDetectsASwappedCredential(t *testing.T) {
	e := keyElsewhere(t)
	e.pairMachine(t, grantFor(5, GradeEnrolled))
	reqs := waiting(t, e.s)
	a := e.s.queuedParts(reqs[0].ID)
	// Another grant built at the same place, as one swapped in would be.
	owner, _ := e.s.DataStore.GetIdentity()
	reg, _ := e.s.DataStore.GetRegistryByIssuer(owner.AID)
	g := grantFor(6, GradeEnrolled)
	other, err := e.s.KeriDriver.(drivers.PreparedIssuer).PrepareCredentialInRegistry(owner.AID, map[string]interface{}{
		"name": g.Label, "label": g.Label, "public_key": g.PublicKey, "grade": string(g.Grade), "i": g.ControllerAID,
		"asset_type": schemas.ControllerGrant.AssetType}, schemas.ControllerGrant.Schema.SAID, g.ControllerAID, nil, reg.RegistrySAID)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString
	b := map[string]string{"credential_b64": b64(other.AcdcRaw), "issuance_b64": b64(other.IssRaw)}
	if _, err := e.s.whatIsToBeSigned(reqs[0].PayloadB64, map[string]string{"credential_b64": b["credential_b64"], "issuance_b64": b["issuance_b64"]}); err == nil {
		t.Fatal("a credential swapped behind the interaction passed the device's check")
	}
	if _, err := e.s.whatIsToBeSigned(reqs[0].PayloadB64, map[string]string{"credential_b64": a["credential_b64"], "issuance_b64": b["issuance_b64"]}); err == nil {
		t.Fatal("an issuance event of another credential passed the device's check")
	}
	// An interaction built to seal one credential with another's issuance.
	payloadA, _ := base64.StdEncoding.DecodeString(reqs[0].PayloadB64)
	ixnA, _ := keri.ParseEvent(payloadA)
	issEvent, _ := keri.VerifyTELEvent(other.IssRaw)
	credA, _ := base64.StdEncoding.DecodeString(a["credential_b64"])
	cred, _ := keri.VerifyCredential(credA)
	mixed, err := keri.BuildInteraction(keri.InteractionInput{Prefix: ixnA.Identifier, PriorSAID: ixnA.PriorSAID, SN: int(ixnA.SN),
		Data: []json.RawMessage{json.RawMessage(`{"i":"` + cred.SAID + `","s":"0","d":"` + issEvent.SAID + `"}`)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.whatIsToBeSigned(b64(mixed), map[string]string{"credential_b64": a["credential_b64"], "issuance_b64": b["issuance_b64"]}); err == nil {
		t.Fatal("an interaction sealing a credential with another's issuance passed the device's check")
	}
	if rec := fulfil(t, e.s, reqs[0], e.seed); rec.Code != http.StatusOK {
		t.Fatalf("the first: %d", rec.Code)
	}
	if _, err := e.s.whatIsToBeSigned(b64(other.IxnRaw), map[string]string{"credential_b64": b["credential_b64"], "issuance_b64": b["issuance_b64"]}); err == nil {
		t.Fatal("an interaction that no longer extends the key log passed the device's check")
	}
}

// With no registry yet and the key elsewhere, the registry is asked for
// first, and the grant once it is made.
func TestARegistryIsAskedForBeforeTheFirstGrant(t *testing.T) {
	e := keyElsewhere(t)
	recordDB(t, e.s).Exec(`DELETE FROM credential_registries`)
	g := grantFor(5, GradeEnrolled)
	if rec := e.pairMachine(t, g); rec.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rec.Code, rec.Body.String())
	}
	reqs := waiting(t, e.s)
	if len(reqs) != 1 || reqs[0].Kind != signingKindRegistry {
		t.Fatalf("what the device is asked first: %+v", reqs)
	}
	if shown, err := checkAsTheDevice(t, e.s, reqs[0]); err != nil || shown["kind"] != "registry" {
		t.Fatalf("the device's check of the registry: %v %v", shown, err)
	}
	if m, _ := awaiting(t, e.s); m[g.ControllerAID] != "the device that holds the identity's key" {
		t.Fatalf("the machine is listed as %q", m[g.ControllerAID])
	}
	if rec := fulfil(t, e.s, reqs[0], e.seed); rec.Code != http.StatusOK {
		t.Fatalf("signing the registry: %d %s", rec.Code, rec.Body.String())
	}
	reqs = waiting(t, e.s)
	if len(reqs) != 1 || reqs[0].Kind != signingKindGrant {
		t.Fatalf("what the device is asked next: %+v", reqs)
	}
	if rec := fulfil(t, e.s, reqs[0], e.seed); rec.Code != http.StatusOK {
		t.Fatalf("signing the grant: %d %s", rec.Code, rec.Body.String())
	}
	if got, _, _ := e.s.controllers().Get(g.ControllerAID); got.CredentialSAID == "" {
		t.Fatal("the machine was not granted once the registry was made")
	}
	keyLogVerifies(t, e.s)
}

// A grant the device refused, or that waited too long, is listed so, for the
// owner to ask again.
func TestARefusedOrExpiredGrantIsListedSo(t *testing.T) {
	e := keyElsewhere(t)
	refused, expired := grantFor(5, GradeEnrolled), grantFor(6, GradeEnrolled)
	e.pairMachine(t, refused)
	r := waiting(t, e.s)[0]
	rec := httptest.NewRecorder()
	e.s.handleRefuseSigningRequest(rec, withID(ownerRequest("POST", "/api/signing-requests/"+r.ID+"/refuse", strings.NewReader(`{}`), e.s), r.ID))
	e.pairMachine(t, expired)
	x := waiting(t, e.s)[0]
	// Time passing: a request's expiry is fixed when it is made.
	recordDB(t, e.s).Exec(`UPDATE signing_requests SET expires_at = ? WHERE id = ?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), x.ID)
	m, _ := awaiting(t, e.s)
	if !strings.Contains(m[refused.ControllerAID], "refused") || !strings.Contains(m[expired.ControllerAID], "expired") {
		t.Fatalf("listed as %q and %q", m[refused.ControllerAID], m[expired.ControllerAID])
	}
}

// A grant waiting with no request behind it is not asked for, and one whose
// request has gone is not issued.
func TestAWaitingGrantNeedsItsRequest(t *testing.T) {
	e := keyElsewhere(t)
	if _, err := e.s.grantController(grantFor(5, GradeEnrolled), time.Now().UTC(), authority{}); err == nil {
		t.Fatal("a grant was asked for, where the key is elsewhere, with no request behind it")
	}
	g := grantFor(6, GradeEnrolled)
	e.pairMachine(t, g)
	req := waiting(t, e.s)[0]
	body, _, _ := e.s.DataStore.GetPendingIssuance(req.ID)
	var p pendingIssuance
	json.Unmarshal([]byte(body), &p)
	p.Spec.Request = nil
	nb, _ := json.Marshal(p)
	recordDB(t, e.s).Exec(`UPDATE pending_issuances SET body=? WHERE signing_request_id=?`, string(nb), req.ID)
	if rec := fulfil(t, e.s, req, e.seed); rec.Code < 400 {
		t.Fatalf("a waiting grant with its request gone was answered %d", rec.Code)
	}
}

// Where the key is elsewhere, an earlier AI agent approved by its owner
// waits for the device rather than failing; one already granted is refused
// before anything is asked for, since its grant could not be withdrawn here.
func TestApprovingWhereTheKeyIsElsewhereWaitsOrRefuses(t *testing.T) {
	w := newTalkWorld(t)
	resetSeenSignatures(t)
	provision := func(name string) string {
		rec := httptest.NewRecorder()
		w.s.router.ServeHTTP(rec, local("POST", "/api/mcp/agents", `{"name":"`+name+`","capabilities":["`+capabilityMessageAgent+`"]}`))
		var made map[string]interface{}
		json.Unmarshal(rec.Body.Bytes(), &made)
		id, _ := made["asset_id"].(string)
		if id == "" {
			t.Fatalf("provisioning %s: %d %s", name, rec.Code, rec.Body.String())
		}
		return id
	}
	earlier, granted := provision("Earlier"), provision("Granted")
	ea, _ := w.s.assetHandler.Store.GetAsset(earlier)
	recordDB(t, w.s).Exec(`DELETE FROM credentials WHERE holder_aid = ?`, ea.PairwiseAID)
	mcpTokensMu.Lock()
	toks := w.s.loadMCPTokens()
	for i := range toks {
		if toks[i].AssetID == earlier {
			toks[i].GrantSAID = ""
		}
	}
	w.s.saveMCPTokens(toks)
	mcpTokensMu.Unlock()
	owner, _ := w.s.DataStore.GetIdentity()
	owner.DerivationIndex += 1000
	w.s.DataStore.SaveIdentity(*owner)
	e := &elsewhere{w: w, s: w.s}
	if rec := e.setCapabilities(t, earlier, capabilityMessageAgent); rec.Code != http.StatusOK {
		t.Fatalf("approving an earlier AI agent where the key is elsewhere: %d %s", rec.Code, rec.Body.String())
	}
	if !w.s.agentGrantPendingFor(earlier) || len(waiting(t, w.s)) != 1 {
		t.Fatal("the approved AI agent is not waiting for the device")
	}
	if rec := e.setCapabilities(t, granted, capabilityMessageAgent); rec.Code != http.StatusConflict {
		t.Fatalf("re-granting an AI agent already granted, where the key is elsewhere, was answered %d", rec.Code)
	}
	if len(waiting(t, w.s)) != 1 {
		t.Fatal("a grant was asked for before re-granting was refused")
	}
}

// An AI agent is not made where the identity's key is on another device: its
// identity is approved by an interaction only that key may sign, and nothing
// is written into the key log unsigned.
func TestAnAIAgentIsNotMadeWhereTheKeyIsElsewhere(t *testing.T) {
	e := keyElsewhere(t)
	owner, _ := e.s.DataStore.GetIdentity()
	before, _ := e.s.DataStore.GetEvents(owner.AID)
	rec := httptest.NewRecorder()
	e.s.router.ServeHTTP(rec, signedFor(t, e.s.thisIdentityAgentsIdentifier(), "POST", "/api/mcp/agents", `{"name":"Here","capabilities":["`+capabilityMessageAgent+`"]}`, testOwnerSeed(), time.Now()))
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
	resetSeenSignatures(t)
	path := filepath.Join(w.s.DataDir, "secureenclave", "root_seed.key")
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o600) })
	if err := w.s.keyCanSign(); !errors.Is(err, errKeyUnavailable) {
		t.Fatalf("an unreadable key reads as %v", err)
	}
	if w.s.keyIsElsewhere() {
		t.Fatal("an unreadable key reads as held elsewhere")
	}
	g := grantFor(5, GradeEnrolled)
	body := `{"controller_aid":"` + g.ControllerAID + `","public_key":"` + g.PublicKey + `","label":"` + g.Label + `","grade":"` + string(g.Grade) + `"}`
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, signedFor(t, w.s.thisIdentityAgentsIdentifier(), "POST", "/api/controllers", body, testOwnerSeed(), time.Now()))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("granting with the key unreadable was answered %d %s", rec.Code, rec.Body.String())
	}
	if len(waiting(t, w.s)) != 0 {
		t.Fatal("a grant was asked of another device, where there is none")
	}
	if got, _, _ := w.s.controllers().Get(g.ControllerAID); got.CredentialPending {
		t.Fatal("the machine was marked as waiting for another device")
	}
	rec = httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, signedFor(t, w.s.thisIdentityAgentsIdentifier(), "POST", "/api/mcp/agents", `{"name":"Later","capabilities":["`+capabilityMessageAgent+`"]}`, testOwnerSeed(), time.Now().Add(time.Second)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("making an AI agent with the key unreadable was answered %d %s", rec.Code, rec.Body.String())
	}
	os.Chmod(path, 0o600)
	if err := w.s.keyCanSign(); err != nil {
		t.Fatalf("once readable again, the stored seed is not the one it was: %v", err)
	}
}

// Where the key is genuinely held on another device, it reads so.
func TestAKeyElsewhereReadsSo(t *testing.T) {
	e := keyElsewhere(t)
	if !e.s.keyIsElsewhere() || !errors.Is(e.s.keyCanSign(), errKeyElsewhere) {
		t.Fatalf("a key elsewhere reads as %v", e.s.keyCanSign())
	}
}

// A registry inception the key log has moved past is built again and asked
// for afresh, as a stale grant is.
func TestAStaleRegistryIsBuiltAgain(t *testing.T) {
	e := keyElsewhere(t)
	recordDB(t, e.s).Exec(`DELETE FROM credential_registries`)
	e.pairMachine(t, grantFor(5, GradeEnrolled))
	req := waiting(t, e.s)[0]
	body, _, _ := e.s.DataStore.GetPendingIssuance(req.ID)
	var p pendingIssuance
	json.Unmarshal([]byte(body), &p)
	p.Registry.Prior = "Ethe-key-log-moved-on"
	nb, _ := json.Marshal(p)
	recordDB(t, e.s).Exec(`UPDATE pending_issuances SET body=? WHERE signing_request_id=?`, string(nb), req.ID)
	if rec := fulfil(t, e.s, req, e.seed); rec.Code != http.StatusConflict {
		t.Fatalf("a stale registry was answered %d %s", rec.Code, rec.Body.String())
	}
	fresh := waiting(t, e.s)
	if len(fresh) != 1 || fresh[0].ID == req.ID || fresh[0].Kind != signingKindRegistry {
		t.Fatalf("the stale registry was not asked for afresh: %+v", fresh)
	}
}
