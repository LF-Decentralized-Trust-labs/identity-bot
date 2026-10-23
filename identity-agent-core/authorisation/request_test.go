package authorisation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/schemas"

	keri "github.com/grapeid/keri-go"
)

const (
	org      = "EOrganisation0123456789ABCDEFGHIJKLMNOPQRSTU"
	registry = "ERegistry0123456789ABCDEFGHIJKLMNOPQRSTUVWXY"
	agentAID = "EAgent0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab"
	telTime  = "2006-01-02T15:04:05.000000-07:00"
)

// world is a machine with a Controller Grant, and what it signs.
type world struct {
	t       *testing.T
	seed    []byte
	machine string
	key     string
	grant   []byte
	said    string
	log     [][]byte
	issued  time.Time
	// body is the body of the request last signed, which the issuer keeps.
	body string
	// issuer, when set, issues what is built next instead of the organisation.
	issuer string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	w := &world{t: t, seed: priv.Seed(), machine: iacrypto.NonTransferableAIDQB64(pub), key: iacrypto.VerkeyQB64(pub)}
	w.issued = time.Now().UTC().Add(-time.Hour)
	w.grant, w.said = w.build(schemas.ControllerGrant.Schema.SAID, w.machine, w.issued, map[string]interface{}{
		"asset_type": "controller", "name": "the laptop", "label": "the laptop", "public_key": w.key, "grade": "enrolled",
	}, nil)
	iss, err := keri.BuildIssuance(keri.IssuanceInput{CredentialSAID: w.said, Registry: registry, DT: w.issued.Format(telTime)})
	if err != nil {
		t.Fatal(err)
	}
	w.log = [][]byte{iss}
	return w
}

func (w *world) build(schema, holder string, at time.Time, attrs map[string]interface{}, edges map[string]interface{}) ([]byte, string) {
	w.t.Helper()
	data := map[string]interface{}{"d": "", "i": holder, "dt": at.Format(telTime)}
	for k, v := range attrs {
		data[k] = v
	}
	raw, _ := json.Marshal(data)
	issuer := w.issuer
	if issuer == "" {
		issuer = org
	}
	in := keri.CredentialInput{SchemaSAID: schema, Issuer: issuer, Recipient: holder, Registry: registry, Data: raw}
	if edges != nil {
		in.Source, _ = json.Marshal(edges)
	}
	acdc, err := keri.BuildCredential(in)
	if err != nil {
		w.t.Fatal(err)
	}
	c, err := keri.VerifyCredential(acdc)
	if err != nil {
		w.t.Fatal(err)
	}
	return acdc, c.SAID
}

// signs is the request the machine signs, as a controller request is signed.
func (w *world) signs(method, path, body string, at time.Time) map[string]interface{} {
	signed := strings.Join([]string{"IA-CONTROLLER-REQ-V1", w.machine, method, path, at.Format(time.RFC3339),
		"", "", "0", iacrypto.Blake3QB64Must([]byte(body))}, "\n")
	sig, err := login.SignString(signed, w.seed)
	if err != nil {
		w.t.Fatal(err)
	}
	asked, err := Asked(body)
	if err != nil {
		w.t.Fatal(err)
	}
	w.body = body
	return map[string]interface{}{"kind": "controller", "signer": w.machine, "signed": signed, "signature": sig, "asked": asked}
}

func (w *world) edge() map[string]interface{} {
	return map[string]interface{}{"authorised_by": map[string]interface{}{"n": w.said, "s": schemas.ControllerGrant.Schema.SAID}}
}

// aGrant is an AI agent grant issued now for a request made a minute ago.
func (w *world) aGrant(req map[string]interface{}, capabilities []string, about string) []byte {
	attrs := map[string]interface{}{"asset_type": "ai_agent", "name": "Research assistant", "capabilities": capabilities, "request": req}
	if about != "" {
		attrs["about"] = about
	}
	acdc, _ := w.build(schemas.AIAgentGrant.Schema.SAID, agentAID, time.Now().UTC(), attrs, w.edge())
	return acdc
}

func (w *world) check(cred []byte) error {
	return Check(Input{Credential: cred, Grant: w.grant, GrantLog: w.log, Body: w.body, HaveBody: true})
}

func ago(d time.Duration) time.Time { return time.Now().UTC().Add(-d) }

const capBody = `{"capabilities":["system.info.read"]}`

func TestARequestThatHoldsPasses(t *testing.T) {
	w := newWorld(t)
	req := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	if err := w.check(w.aGrant(req, []string{"system.info.read"}, "agent-1")); err != nil {
		t.Fatalf("a request that holds was refused: %v", err)
	}
	prov := w.signs("POST", "/api/mcp/agents", `{"name":"Research assistant","capabilities":["system.info.read"]}`, ago(time.Minute))
	if err := w.check(w.aGrant(prov, []string{"system.info.read"}, "")); err != nil {
		t.Fatalf("a provisioning request that holds was refused: %v", err)
	}
}

func TestTheRequestMustBeTheOneSigned(t *testing.T) {
	w := newWorld(t)
	req := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	wider := `{"capabilities":["system.info.read","infra.zone.list"]}`
	req["asked"], _ = Asked(wider)
	cred := w.aGrant(req, []string{"system.info.read", "infra.zone.list"}, "agent-1")
	w.body = wider
	if err := w.check(cred); err == nil {
		t.Fatal("a body other than the one signed was accepted")
	}
	w.body = capBody
	if err := w.check(cred); err == nil {
		t.Fatal("a credential asking for more than the signed body asked for was accepted")
	}
}

func TestTheSignatureMustBeTheGrantsKey(t *testing.T) {
	w := newWorld(t)
	req := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	req["signature"], _ = login.SignString(req["signed"].(string), other.Seed())
	if err := w.check(w.aGrant(req, []string{"system.info.read"}, "agent-1")); err == nil {
		t.Fatal("a signature by another key was accepted")
	}
}

func TestTheSignerMustHoldTheGrant(t *testing.T) {
	w := newWorld(t)
	stranger := newWorld(t)
	req := stranger.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	if err := w.check(w.aGrant(req, []string{"system.info.read"}, "agent-1")); err == nil {
		t.Fatal("a request signed by a machine that does not hold the grant was accepted")
	}
}

func TestTheEdgeMustNameTheGrantGiven(t *testing.T) {
	w := newWorld(t)
	other := newWorld(t)
	req := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	cred := w.aGrant(req, []string{"system.info.read"}, "agent-1")
	if err := Check(Input{Credential: cred, Grant: other.grant, GrantLog: other.log, Body: w.body, HaveBody: true}); err == nil {
		t.Fatal("a grant other than the one the edge names was accepted")
	}
}

func TestWhatWasGrantedMustBeWhatWasAskedFor(t *testing.T) {
	w := newWorld(t)
	req := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	if err := w.check(w.aGrant(req, []string{"system.info.read", "infra.zone.list"}, "agent-1")); err == nil {
		t.Fatal("more capabilities than were asked for were accepted")
	}
	if err := w.check(w.aGrant(req, []string{"system.info.read"}, "agent-2")); err == nil {
		t.Fatal("a grant to another AI agent than the one asked about was accepted")
	}
	prov := w.signs("POST", "/api/mcp/agents", `{"name":"Someone else","capabilities":["system.info.read"]}`, ago(time.Minute))
	if err := w.check(w.aGrant(prov, []string{"system.info.read"}, "")); err == nil {
		t.Fatal("a grant to an AI agent named differently from the one asked for was accepted")
	}
	limited := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", `{"capabilities":["system.info.read"],"resource_constraints":{"system.info.read":{"host":["a"]}}}`, ago(time.Minute))
	if err := w.check(w.aGrant(limited, []string{"system.info.read"}, "agent-1")); err == nil {
		t.Fatal("a grant without the limits that were asked for was accepted")
	}
}

func TestTheRequestMustComeBeforeTheIssueAndAfterTheGrant(t *testing.T) {
	w := newWorld(t)
	late := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, time.Now().UTC().Add(2*Skew))
	if err := w.check(w.aGrant(late, []string{"system.info.read"}, "agent-1")); err == nil {
		t.Fatal("a request made after the credential was issued was accepted")
	}
	stale := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(2*Skew))
	if err := w.check(w.aGrant(stale, []string{"system.info.read"}, "agent-1")); err == nil {
		t.Fatal("a request made long before the credential was issued was accepted")
	}
	// A grant dated after the request it is said to have authorised.
	w.issued = time.Now().UTC().Add(time.Hour)
	w.grant, w.said = w.build(schemas.ControllerGrant.Schema.SAID, w.machine, w.issued, map[string]interface{}{
		"asset_type": "controller", "name": "the laptop", "label": "the laptop", "public_key": w.key, "grade": "enrolled",
	}, nil)
	iss, _ := keri.BuildIssuance(keri.IssuanceInput{CredentialSAID: w.said, Registry: registry, DT: w.issued.Format(telTime)})
	w.log = [][]byte{iss}
	early := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	if err := w.check(w.aGrant(early, []string{"system.info.read"}, "agent-1")); err == nil {
		t.Fatal("a request made before the machine was granted was accepted")
	}
}

func TestARevokedGrantAuthorisesNothingIssuedAfter(t *testing.T) {
	w := newWorld(t)
	iss, _ := keri.VerifyTELEvent(w.log[0])
	req := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	cred := w.aGrant(req, []string{"system.info.read"}, "agent-1")
	revokedEarlier, _ := keri.BuildRevocation(keri.RevocationInput{CredentialSAID: w.said, Registry: registry, PriorISSSAID: iss.SAID,
		DT: ago(30 * time.Second).Add(-time.Minute).Format(telTime)})
	if err := Check(Input{Credential: cred, Grant: w.grant, GrantLog: [][]byte{w.log[0], revokedEarlier}, Body: w.body, HaveBody: true}); err == nil {
		t.Fatal("a credential issued after its grant was revoked was accepted")
	}
	revokedLater, _ := keri.BuildRevocation(keri.RevocationInput{CredentialSAID: w.said, Registry: registry, PriorISSSAID: iss.SAID,
		DT: time.Now().UTC().Add(time.Hour).Format(telTime)})
	if err := Check(Input{Credential: cred, Grant: w.grant, GrantLog: [][]byte{w.log[0], revokedLater}, Body: w.body, HaveBody: true}); err != nil {
		t.Fatalf("a grant revoked after the credential was issued withdrew it: %v", err)
	}
}

func TestABodyApprovalMustNameTheMachineApproved(t *testing.T) {
	w := newWorld(t)
	approve := func(bid, about string) []byte {
		req := w.signs("POST", "/api/mcp/agents/agent-1/bodies/"+bid+"/approve", "", ago(time.Minute))
		acdc, _ := w.build(schemas.AIAgentBody.Schema.SAID, agentAID, time.Now().UTC(), map[string]interface{}{
			"asset_type": "ai_agent", "name": "Research assistant", "host": "BHost", "verkey": "DKey",
			"keys_digest": "EDigest", "grade": "software", "request": req, "about": about,
		}, w.edge())
		return acdc
	}
	if err := w.check(approve("body-1", "body-1")); err != nil {
		t.Fatalf("a body approval that holds was refused: %v", err)
	}
	if err := w.check(approve("body-1", "body-2")); err == nil {
		t.Fatal("a body credential for another machine than the one approved was accepted")
	}
}

func TestAnOwnersRequestIsCheckedAgainstTheOwnersKey(t *testing.T) {
	w := newWorld(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed := strings.Join([]string{"IA-REQ-V1", "PUT", "/api/mcp/agents/agent-1/capabilities", ago(time.Minute).Format(time.RFC3339),
		iacrypto.Blake3QB64Must([]byte(capBody))}, "\n")
	sig, _ := login.SignString(signed, priv.Seed())
	asked, _ := Asked(capBody)
	req := map[string]interface{}{"kind": "owner", "signer": org, "signed": signed, "signature": sig, "asked": asked}
	acdc, _ := w.build(schemas.AIAgentGrant.Schema.SAID, agentAID, time.Now().UTC(), map[string]interface{}{
		"asset_type": "ai_agent", "name": "Research assistant", "capabilities": []string{"system.info.read"}, "request": req, "about": "agent-1",
	}, nil)
	if err := Check(Input{Credential: acdc, OwnerKey: iacrypto.VerkeyQB64(pub), Body: capBody, HaveBody: true}); err != nil {
		t.Fatalf("the owner's own request was refused: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := Check(Input{Credential: acdc, OwnerKey: iacrypto.VerkeyQB64(other), Body: capBody, HaveBody: true}); err == nil {
		t.Fatal("an owner's request was accepted against another key")
	}
}

func TestACredentialWithNoRequestSaysSo(t *testing.T) {
	w := newWorld(t)
	acdc, _ := w.build(schemas.AIAgentGrant.Schema.SAID, agentAID, time.Now().UTC(), map[string]interface{}{
		"asset_type": "ai_agent", "name": "Research assistant", "capabilities": []string{},
	}, nil)
	if err := Check(Input{Credential: acdc}); !errors.Is(err, ErrNoRequest) {
		t.Fatalf("a credential with no request read as %v", err)
	}
}

func TestAnAlteredCredentialIsRefused(t *testing.T) {
	w := newWorld(t)
	req := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	cred := w.aGrant(req, []string{"system.info.read"}, "agent-1")
	altered := []byte(strings.Replace(string(cred), "Research assistant", "Research assistanT", 1))
	if err := w.check(altered); err == nil {
		t.Fatal("an altered credential was accepted")
	}
}

// The string must name the machine that signed it.
func TestTheSignedStringMustNameItsSigner(t *testing.T) {
	w := newWorld(t)
	other := newWorld(t)
	signed := strings.Join([]string{"IA-CONTROLLER-REQ-V1", other.machine, "PUT", "/api/mcp/agents/agent-1/capabilities",
		ago(time.Minute).Format(time.RFC3339), "", "", "0", iacrypto.Blake3QB64Must([]byte(capBody))}, "\n")
	sig, _ := login.SignString(signed, w.seed)
	asked, _ := Asked(capBody)
	w.body = capBody
	req := map[string]interface{}{"kind": "controller", "signer": w.machine, "signed": signed, "signature": sig, "asked": asked}
	if err := w.check(w.aGrant(req, []string{"system.info.read"}, "agent-1")); err == nil {
		t.Fatal("a string naming another machine was accepted from this one")
	}
}

// Another grant of the same machine is still not the grant the edge names.
func TestAnotherGrantOfTheSameMachineIsNotTheOneNamed(t *testing.T) {
	w := newWorld(t)
	req := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	cred := w.aGrant(req, []string{"system.info.read"}, "agent-1")
	second, said := w.build(schemas.ControllerGrant.Schema.SAID, w.machine, w.issued.Add(time.Second), map[string]interface{}{
		"asset_type": "controller", "name": "the laptop", "label": "the laptop", "public_key": w.key, "grade": "enrolled",
	}, nil)
	iss, _ := keri.BuildIssuance(keri.IssuanceInput{CredentialSAID: said, Registry: registry, DT: w.issued.Format(telTime)})
	if err := Check(Input{Credential: cred, Grant: second, GrantLog: [][]byte{iss}, Body: w.body, HaveBody: true}); err == nil {
		t.Fatal("a grant other than the one the edge names was accepted")
	}
}

// A grant held by another machine does not authorise this one, even naming
// the same key.
func TestAGrantHeldByAnotherMachineDoesNotCount(t *testing.T) {
	w := newWorld(t)
	other := newWorld(t)
	w.grant, w.said = w.build(schemas.ControllerGrant.Schema.SAID, other.machine, w.issued, map[string]interface{}{
		"asset_type": "controller", "name": "the laptop", "label": "the laptop", "public_key": w.key, "grade": "enrolled",
	}, nil)
	iss, _ := keri.BuildIssuance(keri.IssuanceInput{CredentialSAID: w.said, Registry: registry, DT: w.issued.Format(telTime)})
	w.log = [][]byte{iss}
	req := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	if err := w.check(w.aGrant(req, []string{"system.info.read"}, "agent-1")); err == nil {
		t.Fatal("a request was accepted on a grant held by another machine")
	}
}

// The edge must name a Controller Grant.
func TestTheEdgeMustNameAControllerGrant(t *testing.T) {
	w := newWorld(t)
	req := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	attrs := map[string]interface{}{"asset_type": "ai_agent", "name": "Research assistant", "capabilities": []string{"system.info.read"}, "request": req, "about": "agent-1"}
	cred, _ := w.build(schemas.AIAgentGrant.Schema.SAID, agentAID, time.Now().UTC(), attrs,
		map[string]interface{}{"authorised_by": map[string]interface{}{"n": w.said, "s": schemas.AIAgentGrant.Schema.SAID}})
	if err := w.check(cred); err == nil {
		t.Fatal("an edge naming a credential as something other than a Controller Grant was accepted")
	}
}

// A request made after the machine's grant lapsed authorises nothing.
func TestARequestAfterTheGrantLapsedAuthorisesNothing(t *testing.T) {
	w := newWorld(t)
	w.grant, w.said = w.build(schemas.ControllerGrant.Schema.SAID, w.machine, w.issued, map[string]interface{}{
		"asset_type": "controller", "name": "the laptop", "label": "the laptop", "public_key": w.key, "grade": "scoped",
		"valid_until": ago(10 * time.Minute).Format(time.RFC3339),
	}, nil)
	iss, _ := keri.BuildIssuance(keri.IssuanceInput{CredentialSAID: w.said, Registry: registry, DT: w.issued.Format(telTime)})
	w.log = [][]byte{iss}
	req := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	if err := w.check(w.aGrant(req, []string{"system.info.read"}, "agent-1")); err == nil {
		t.Fatal("a request made after the grant lapsed was accepted")
	}
}

// A grant issued by someone other than the credential's issuer authorises
// nothing it issued.
func TestTheGrantMustBeTheIssuersOwn(t *testing.T) {
	w := newWorld(t)
	w.issuer = "EAnotherIssuer0123456789ABCDEFGHIJKLMNOPQRS"
	w.grant, w.said = w.build(schemas.ControllerGrant.Schema.SAID, w.machine, w.issued, map[string]interface{}{
		"asset_type": "controller", "name": "the laptop", "label": "the laptop", "public_key": w.key, "grade": "enrolled",
	}, nil)
	w.issuer = ""
	iss, _ := keri.BuildIssuance(keri.IssuanceInput{CredentialSAID: w.said, Registry: registry, DT: w.issued.Format(telTime)})
	w.log = [][]byte{iss}
	req := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	if err := w.check(w.aGrant(req, []string{"system.info.read"}, "agent-1")); err == nil {
		t.Fatal("a grant issued by someone else was accepted")
	}
}

// Without the body, everything else is checked and the link to what was
// signed is reported as not shown.
func TestWithoutTheBodyTheLinkToWhatWasSignedIsNotShown(t *testing.T) {
	w := newWorld(t)
	req := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	cred := w.aGrant(req, []string{"system.info.read"}, "agent-1")
	if err := Check(Input{Credential: cred, Grant: w.grant, GrantLog: w.log}); !errors.Is(err, ErrBodyWithheld) {
		t.Fatalf("a check without the body read as %v", err)
	}
	if d, err := RequestDigest(cred); err != nil || d != iacrypto.Blake3QB64Must([]byte(req["signed"].(string))) {
		t.Fatalf("the request's digest: %q %v", d, err)
	}
}

// keyLog is an issuer's key log in which each given transaction event is
// sealed by its own interaction, in the order given.
func keyLog(t *testing.T, events ...[]byte) [][]byte {
	t.Helper()
	var out [][]byte
	for i, raw := range events {
		ev, err := keri.VerifyTELEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(map[string]interface{}{"t": "ixn", "s": strconv.FormatInt(int64(i+1), 16),
			"a": []map[string]interface{}{{"i": ev.Subject, "s": strconv.FormatInt(int64(ev.SN), 16), "d": ev.SAID}}})
		out = append(out, b)
	}
	return out
}

// With the issuer's key log, the order of issue and revocation is read from
// where each is anchored, whatever times the events assert.
func TestTheKeyLogDecidesTheOrder(t *testing.T) {
	w := newWorld(t)
	req := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	cred := w.aGrant(req, []string{"system.info.read"}, "agent-1")
	c, _ := keri.VerifyCredential(cred)
	credIss, _ := keri.BuildIssuance(keri.IssuanceInput{CredentialSAID: c.SAID, Registry: registry, DT: time.Now().UTC().Format(telTime)})
	gIss, _ := keri.VerifyTELEvent(w.log[0])
	// Revoked, by its own say-so, an hour after the credential, but anchored
	// before it.
	rev, _ := keri.BuildRevocation(keri.RevocationInput{CredentialSAID: w.said, Registry: registry, PriorISSSAID: gIss.SAID,
		DT: time.Now().UTC().Add(time.Hour).Format(telTime)})
	check := func(kel [][]byte) error {
		return Check(Input{Credential: cred, Grant: w.grant, GrantLog: [][]byte{w.log[0], rev}, Body: w.body, HaveBody: true,
			IssuerKEL: kel, CredentialLog: [][]byte{credIss}})
	}
	if err := check(keyLog(t, w.log[0], rev, credIss)); err == nil {
		t.Fatal("a credential anchored after its grant's revocation was accepted")
	}
	if err := check(keyLog(t, w.log[0], credIss, rev)); err != nil {
		t.Fatalf("a credential anchored before its grant's revocation was refused: %v", err)
	}
	if err := check(keyLog(t, credIss, w.log[0], rev)); err == nil {
		t.Fatal("a credential anchored before its grant was issued was accepted")
	}
	if err := check(keyLog(t, w.log[0], rev)); err == nil {
		t.Fatal("a credential whose issue is not anchored was accepted")
	}
}

// What the credential says was asked for may not add to what the body asked.
func TestTheCredentialMayNotAddToWhatWasAsked(t *testing.T) {
	w := newWorld(t)
	req := w.signs("PUT", "/api/mcp/agents/agent-1/capabilities", capBody, ago(time.Minute))
	asked := req["asked"].(map[string]json.RawMessage)
	asked["nonce"] = json.RawMessage(`"n-added-later"`)
	if err := w.check(w.aGrant(req, []string{"system.info.read"}, "agent-1")); err == nil {
		t.Fatal("a credential claiming more was asked than the body asked was accepted")
	}
}
