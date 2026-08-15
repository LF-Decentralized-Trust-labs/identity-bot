package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/backup"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
)

// An employee signs in to their organisation's website, and a stranger does not.
//
// Every part of this chain existed and no test ran the whole of it, so what each
// piece did in the presence of the others was a matter of reading rather than
// observation. Reading it is what produced two retracted findings: a grep for
// the membership gate's function found no callers, because the caller is in
// another repository behind an extension seam, and the conclusion drawn was that
// the policy was never enforced. It is enforced. This runs it.
//
// The chain, and every link is the production one:
//
//	a root seed on the person's device
//	  → a pairwise key derived from it at the relationship's index
//	  → an assertion signed with that key over the canonical body
//	  → the site posts it to the agent
//	  → the agent resolves the key from the identifier's own did.json
//	  → the agent checks the signature, the nonce, the audience, the freshness
//	  → the agent asks the membership resolver whether this identifier is an employee
//	  → admitted, with the roster's own answer for who they are
type rosterResolver struct{ active map[string]bool }

func (r rosterResolver) Admit(aid, _ string) (bool, string) {
	if r.active[aid] {
		return true, ""
	}
	return false, "not an active employee"
}

func (r rosterResolver) MemberInfo(aid, _ string) (map[string]string, bool) {
	if !r.active[aid] {
		return nil, false
	}
	return map[string]string{"role": "editor", "display_name": "Alice"}, true
}

// theirAgent is the person's side: a root seed, and a relationship whose key is
// derived from it. Returns the handler that can sign, and the relationship.
func theirAgent(t *testing.T, index int) (*login.Handler, *login.SiteRelationship, ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()

	root := make([]byte, 64)
	for i := range root {
		root[i] = byte(i + 7)
	}
	if err := secureenclave.StoreRootSeed(dir, root); err != nil {
		t.Fatalf("store root seed: %v", err)
	}

	// The same derivation the agent uses, so the public key below is genuinely
	// the one the assertion will be signed with.
	seed, err := backup.DerivePairwiseSeed(root, index, 0)
	if err != nil {
		t.Fatalf("derive pairwise seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize])
	pub := priv.Public().(ed25519.PublicKey)

	h, err := login.NewHandler(dir, nil)
	if err != nil {
		t.Fatalf("login handler: %v", err)
	}
	rel := &login.SiteRelationship{
		SiteAID:           "ESiteAID",
		PairwiseAID:       "E" + base64.RawURLEncoding.EncodeToString(pub)[:43],
		RelationshipIndex: index,
		DisplayName:       "Alice",
		Email:             "alice@example.com",
	}
	return h, rel, pub
}

// theirKeyPublished stands in for the relay that serves an identifier's did.json.
// The verifier resolves the signing key from there rather than being handed it.
func theirKeyPublished(t *testing.T, aid string, pub ed25519.PublicKey) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/did.json") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verificationMethod": []map[string]any{{
				"publicKeyJwk": map[string]string{
					"x": base64.RawURLEncoding.EncodeToString(pub),
				},
			}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// theirOrganisation is the organisation's side: an agent holding a website asset
// whose sign-in policy says only its employees may in.
func theirOrganisation(t *testing.T, roster map[string]bool) *CoreServer {
	t.Helper()
	ah, err := asset.NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("asset handler: %v", err)
	}
	if err := ah.Store.UpsertAsset(asset.Asset{
		ID: "the-website", PairwiseAID: "ESiteAID",
		Policy: asset.EnrollmentPolicy{
			Mode:             asset.EnrollmentInvite,
			MembershipSource: "roster_e2e",
		},
	}); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	RegisterMembershipResolver("roster_e2e", rosterResolver{active: roster})

	s := &CoreServer{challenges: map[string]login.ChallengeBundle{}}
	s.assetHandler = ah
	return s
}

// signIn runs one whole attempt and returns what the organisation answered.
func signIn(t *testing.T, s *CoreServer, h *login.Handler, rel *login.SiteRelationship,
	relayURL string) (int, string) {
	t.Helper()

	const token = "session-1"
	bundle := login.ChallengeBundle{
		SiteAID:              "ESiteAID",
		Audience:             "https://portal.example",
		Nonce:                "a-nonce-the-site-invented",
		RequestedDisclosures: []string{"display_name", "email"},
		SessionToken:         token,
	}
	s.challengeMu.Lock()
	s.challenges[token] = bundle
	s.challengeMu.Unlock()

	rel.RelayOOBI = relayURL + "/oobi/" + rel.PairwiseAID
	a, err := h.BuildAssertion(rel, &bundle, nil)
	if err != nil {
		t.Fatalf("build assertion: %v", err)
	}

	body, _ := json.Marshal(a)
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/login/callback?session=%s", token), strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	s.handleLoginCallback(w, req)
	return w.Code, w.Body.String()
}

func TestAnActiveEmployeeSignsIn(t *testing.T) {
	h, rel, pub := theirAgent(t, 1000001)
	relay := theirKeyPublished(t, rel.PairwiseAID, pub)
	s := theirOrganisation(t, map[string]bool{rel.PairwiseAID: true})

	code, body := signIn(t, s, h, rel, relay.URL)
	if code != http.StatusOK {
		t.Fatalf("an active employee was refused: %d %s", code, body)
	}

	s.challengeMu.Lock()
	st := s.challengeStatus["session-1"]
	s.challengeMu.Unlock()
	if st["status"] != "complete" {
		t.Fatalf("status is %v, want complete: %v", st["status"], st)
	}
	// The roster's own answer for who this is, so the site never reads it.
	info, _ := st["member_info"].(map[string]string)
	if info["role"] != "editor" {
		t.Errorf("member_info did not carry the roster's role: %v", st["member_info"])
	}
}

// The whole point of the gate: a correctly signed assertion from somebody who
// is not an employee proves who they are and does not get them in.
func TestSomebodyWhoIsNotAnEmployeeIsRefused(t *testing.T) {
	h, rel, pub := theirAgent(t, 1000002)
	relay := theirKeyPublished(t, rel.PairwiseAID, pub)
	s := theirOrganisation(t, map[string]bool{}) // nobody on the roster

	code, body := signIn(t, s, h, rel, relay.URL)
	if code == http.StatusOK {
		t.Fatal("a stranger with a valid signature was admitted")
	}
	if code != http.StatusForbidden {
		t.Errorf("expected 403 for a policy refusal, got %d: %s", code, body)
	}
}

// Removing somebody takes effect on their next sign-in. This is the property
// that decides whether the roster is the authority or merely a record.
func TestRemovingSomebodyStopsThemSigningIn(t *testing.T) {
	h, rel, pub := theirAgent(t, 1000003)
	relay := theirKeyPublished(t, rel.PairwiseAID, pub)
	roster := map[string]bool{rel.PairwiseAID: true}
	s := theirOrganisation(t, roster)

	if code, body := signIn(t, s, h, rel, relay.URL); code != http.StatusOK {
		t.Fatalf("employee refused while on the roster: %d %s", code, body)
	}

	delete(roster, rel.PairwiseAID) // they leave

	if code, _ := signIn(t, s, h, rel, relay.URL); code == http.StatusOK {
		t.Fatal("somebody removed from the roster still signed in")
	}
}

// A signature that does not match the key the identifier publishes is refused
// before any policy is consulted — authentication precedes authorisation.
func TestAForgedSignatureNeverReachesTheGate(t *testing.T) {
	h, rel, _ := theirAgent(t, 1000004)
	// Publish somebody else's key for this identifier.
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	relay := theirKeyPublished(t, rel.PairwiseAID, otherPub)
	s := theirOrganisation(t, map[string]bool{rel.PairwiseAID: true}) // on the roster!

	code, _ := signIn(t, s, h, rel, relay.URL)
	if code == http.StatusOK {
		t.Fatal("an assertion signed by the wrong key was admitted")
	}
	if code != http.StatusUnauthorized {
		t.Errorf("expected 401 for a bad signature, got %d", code)
	}
}

// The refusal a stranger sees says nothing about why.
//
// "not an active employee", returned to whoever asked, is an oracle: anybody
// who can reach the endpoint learns whether an identifier they nominate works
// at this organisation, without being able to sign in as them. The
// organisation still needs the specific reason, so it goes to the challenge
// status its own app reads.
func TestARefusalTellsTheCallerNothingAndTheOrganisationEverything(t *testing.T) {
	h, rel, pub := theirAgent(t, 1000005)
	relay := theirKeyPublished(t, rel.PairwiseAID, pub)
	s := theirOrganisation(t, map[string]bool{})

	_, body := signIn(t, s, h, rel, relay.URL)

	if strings.Contains(strings.ToLower(body), "employee") {
		t.Errorf("the refusal told the caller which gate refused: %q", body)
	}

	s.challengeMu.Lock()
	st := s.challengeStatus["session-1"]
	s.challengeMu.Unlock()
	if got, _ := st["reason"].(string); !strings.Contains(got, "not an active employee") {
		t.Errorf("the organisation was not told why either, which is the other failure: %v", st)
	}
}
