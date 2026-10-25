package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/login"
)

// The organisation's own key registry, served the way a website's sign-in
// reaches it: /_register to publish a key, /public/{aid}/did.json to read it.
func theOrganisationsRegistry(t *testing.T, s *CoreServer) *httptest.Server {
	t.Helper()
	r := chi.NewRouter()
	s.mountPublicDidWebsRoutes(r)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

// theirKeyLog is the signed key log theirAgent(t, index)'s relationship sends.
func theirKeyLog(t *testing.T, index int) (aid, keyLog, pubB64 string) {
	t.Helper()
	h, rel, pub := theirAgent(t, index)
	a, err := h.BuildAssertion(rel, &login.ChallengeBundle{Audience: "x", Nonce: "y"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rel.PairwiseAID, a.PKEL, base64.RawURLEncoding.EncodeToString(pub)
}

func register(t *testing.T, registry *httptest.Server, aid, pubB64, keyLog string) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"aid": aid, "public_key_b64": pubB64, "key_log": keyLog})
	resp, err := http.Post(registry.URL+"/_register", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func publishedKey(t *testing.T, registry *httptest.Server, aid string) string {
	t.Helper()
	resp, err := http.Get(registry.URL + "/public/" + aid + "/did.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var doc struct {
		VerificationMethod []struct {
			PublicKeyJwk struct {
				X string `json:"x"`
			} `json:"publicKeyJwk"`
		} `json:"verificationMethod"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if len(doc.VerificationMethod) == 0 {
		return ""
	}
	return doc.VerificationMethod[0].PublicKeyJwk.X
}

// Somebody who knows an employee's identifier cannot sign in as them.
//
// An employee's identifier is on the roster, and a roster identifier is not one
// of the organisation's own assets. The registry answered for any such
// identifier with whatever key was last published against it, by anybody, and
// the sign-in check took the key from there. So publishing your own key against
// an employee's identifier and signing with it was a sign-in as that employee.
func TestNobodyCanSignInAsAnEmployeeByPublishingAKeyForThem(t *testing.T) {
	employee, _, _ := theirKeyLog(t, 1000101)
	s := theirOrganisation(t, map[string]bool{employee: true})
	registry := theOrganisationsRegistry(t, s)

	// The attacker holds a real identity of their own, and its signed log.
	_, attackerLog, attackerPub := theirKeyLog(t, 1000102)

	// Publishing a key for somebody else's identifier is refused: with no log,
	// and with the attacker's own log, which derives the attacker, not them.
	if code, _ := register(t, registry, employee, attackerPub, ""); code == http.StatusOK {
		t.Error("a key was published for an identifier with no key log at all")
	}
	if code, _ := register(t, registry, employee, attackerPub, attackerLog); code == http.StatusOK {
		t.Error("a key was published for an identifier the publisher does not control")
	}
	if got := publishedKey(t, registry, employee); got != "" {
		t.Errorf("the registry answers for the employee with a key they never published: %s", got)
	}

	// And an assertion naming the employee, signed with the attacker's key,
	// does not get them in, whatever log it carries and wherever it points.
	const token = "session-1"
	bundle := login.ChallengeBundle{SiteAID: "ESiteAID", Audience: "https://portal.example",
		Nonce: "a-nonce", SessionToken: token}
	s.challengeMu.Lock()
	s.challenges[token] = bundle
	s.challengeMu.Unlock()
	forged := login.Assertion{
		V: "IALOGIN10JSON", T: "login-assertion", I: employee,
		RelationshipAIDOOBI: registry.URL + "/public/oobi/" + employee,
		Audience:            bundle.Audience, Nonce: bundle.Nonce,
		Dt:          time.Now().UTC().Format(time.RFC3339),
		Disclosures: map[string]string{}, PresentedACDCs: []interface{}{},
		PKEL: attackerLog,
	}
	if err := login.SignAssertion(&forged, theirSeed(t, 1000102)); err != nil {
		t.Fatal(err)
	}
	code, answer := postAssertion(t, s, token, &forged)
	if code == http.StatusOK {
		t.Fatalf("somebody signed in as an employee with their own key: %s", answer)
	}
	if code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", code, answer)
	}
	s.challengeMu.Lock()
	st := s.challengeStatus[token]
	s.challengeMu.Unlock()
	if st["status"] == "complete" {
		t.Fatalf("the sign-in was recorded as complete: %v", st)
	}
}

// An identity that publishes its own key, with the log that proves it, is
// answered for — and still is after the agent restarts.
func TestAPublishedKeyIsProvedAndSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	aid, keyLog, pub := theirKeyLog(t, 1000103)

	first := &CoreServer{DataDir: dir}
	registry := theOrganisationsRegistry(t, first)
	if code, body := register(t, registry, aid, pub, keyLog); code != http.StatusOK {
		t.Fatalf("a key published with its own proving log was refused: %d %s", code, body)
	}
	if got := publishedKey(t, registry, aid); got != pub {
		t.Fatalf("the registry answers %q, want the published key %q", got, pub)
	}

	// A wrong key alongside the right log is refused.
	_, _, otherPub := theirKeyLog(t, 1000104)
	if code, _ := register(t, registry, aid, otherPub, keyLog); code == http.StatusOK {
		t.Error("a key the log does not hold was accepted alongside it")
	}

	restarted := &CoreServer{DataDir: dir}
	if got := publishedKey(t, theOrganisationsRegistry(t, restarted), aid); got != pub {
		t.Fatalf("after a restart the registry answers %q, want %q", got, pub)
	}
}

// A held log is never replaced by a different identity's history, and a
// longer one is never rolled back to a shorter one.
func TestAHeldKeyLogIsOnlyEverCarriedForward(t *testing.T) {
	enc := func(events ...string) string {
		b, _ := json.Marshal(login.KeyLog{RawEventsB64: events, CesrSignatures: make([]string, len(events))})
		return base64.RawURLEncoding.EncodeToString(b)
	}
	cases := []struct {
		held, next string
		ok         bool
	}{
		{enc("icp"), enc("icp"), true},
		{enc("icp"), enc("icp", "rot"), true},
		{enc("icp", "rot"), enc("icp"), false},
		{enc("icp"), enc("other"), false},
		{enc("icp", "rot"), enc("icp", "fork"), false},
	}
	for i, c := range cases {
		_, err := mayReplace(c.held, c.next)
		if (err == nil) != c.ok {
			t.Errorf("case %d: replace allowed=%v, want %v (%v)", i, err == nil, c.ok, err)
		}
	}
}

// A full registry refuses a new identity and still carries a held one forward,
// so strangers minting identities cannot spend this agent's disk.
func TestAFullRegistryRefusesNewcomersButNotThoseItHolds(t *testing.T) {
	reg := &keyRegistry{m: map[string]registeredKey{}}
	for i := 0; i < maxRegisteredKeys; i++ {
		reg.m[fmt.Sprintf("E%d", i)] = registeredKey{}
	}
	held, _, _ := theirKeyLog(t, 1000107)
	_, log, pub := theirKeyLog(t, 1000107)
	delete(reg.m, "E0")
	if _, err := reg.put(held, registeredKey{KeyLog: log, PublicKeyB64: pub}); err != nil {
		t.Fatalf("filling the last place was refused: %v", err)
	}
	if code, err := reg.put("ENewcomer", registeredKey{KeyLog: log}); err == nil || code != http.StatusInsufficientStorage {
		t.Fatalf("a full registry accepted a newcomer (%d, %v)", code, err)
	}
	if _, err := reg.put(held, registeredKey{KeyLog: log, PublicKeyB64: pub}); err != nil {
		t.Fatalf("a held identity could not be carried forward in a full registry: %v", err)
	}
}

// A verifier in another language asks this agent what key a log establishes,
// rather than keeping a second implementation of the check.
func TestAKeyLogIsCheckedForAVerifierThatCannot(t *testing.T) {
	aid, keyLog, pub := theirKeyLog(t, 1000105)
	_, otherLog, _ := theirKeyLog(t, 1000106)
	registry := theOrganisationsRegistry(t, &CoreServer{})

	ask := func(aid, log string) (int, map[string]string) {
		body, _ := json.Marshal(map[string]string{"aid": aid, "key_log": log})
		resp, err := http.Post(registry.URL+"/public/login/key", "application/json",
			strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if code, out := ask(aid, keyLog); code != http.StatusOK || out["public_key_b64"] != pub {
		t.Fatalf("a genuine log was not answered with its key: %d %v", code, out)
	}
	if code, out := ask(aid, otherLog); code == http.StatusOK {
		t.Fatalf("another identity's log was answered for this one: %v", out)
	}
}
