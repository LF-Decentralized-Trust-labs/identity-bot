package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/asset"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

// The whole sign-in, with nothing standing in for either side.
//
// The organisation is founded, delegates a website asset from its own key and
// anchors that approval in its log. Its Identity Agent serves the introductions,
// the signed challenge and the callback over HTTP, exactly as it mounts them.
// The person's Identity Agent, holding only a root seed, fetches the challenge,
// checks the site's key against the site's own log, checks the organisation's
// approval of the site against the organisation's own log, derives the
// relationship's key, signs, and posts to the callback. Each check in that chain
// is tested on its own elsewhere; this is the one place they run together.
type aWebsiteWorld struct {
	org    *CoreServer
	srv    *httptest.Server
	roster map[string]bool
}

func anOrganisationWithAWebsite(t *testing.T, policy asset.EnrollmentPolicy) *aWebsiteWorld {
	t.Helper()
	s, _ := foundedWith(t, agentWithDerivedIdentity(t), nil, 0)
	owner, _ := s.DataStore.GetIdentity()
	root := owner.AID

	const index = 11
	pub, next, err := asset.DeriveAssetKeypair(s.DataDir, index)
	if err != nil {
		t.Fatal(err)
	}
	dip, err := s.KeriDriver.CreateDelegatedInception(iacrypto.VerkeyQB64(pub), iacrypto.VerkeyQB64(next), "the-website", root)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.saveDelegationAnchor(root, dip); err != nil {
		t.Fatal(err)
	}
	ah, err := asset.NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ah.Store.UpsertAsset(asset.Asset{
		ID: "the-website", DisplayName: "the-website", AssetType: "website",
		PairwiseAID: dip.AID, DelegationModel: "delegated", DelegatorAID: root,
		SigningIndex: index, Policy: policy,
	}); err != nil {
		t.Fatal(err)
	}
	s.assetHandler = ah
	s.challenges = map[string]login.ChallengeBundle{}

	w := &aWebsiteWorld{org: s, roster: map[string]bool{}}
	RegisterMembershipResolver("roster_the_website", rosterResolver{active: w.roster})

	r := chi.NewRouter()
	r.Get("/public/oobi/{aid}", s.handleOobiServe)
	r.Get("/i/{token}", s.handleChallengeBundleServe)
	r.Post("/api/login/callback", s.handleLoginCallback)
	w.srv = httptest.NewServer(r)
	t.Cleanup(w.srv.Close)
	return w
}

// aPersonsIdentityAgent holds a root seed and nothing else about the site.
func aPersonsIdentityAgent(t *testing.T) *login.Handler {
	t.Helper()
	h, _, _ := theirAgent(t, 1000601)
	h.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	return h
}

func (w *aWebsiteWorld) challenge(t *testing.T) login.StartLoginRequest {
	t.Helper()
	token, _, code, msg := w.org.createSignedAssetChallenge("the-website", "https://portal.example",
		[]string{"display_name"}, w.srv.URL)
	if code != 0 {
		t.Fatalf("the organisation could not issue a challenge: %d %s", code, msg)
	}
	return login.StartLoginRequest{SessionToken: token, RPSessionURL: w.srv.URL}
}

// A member of the organisation signs in to its members-only website: the
// person's Identity Agent verifies the site and the organisation's approval of
// it, presents the identity the organisation enrolled, and is admitted.
func TestAMemberSignsInToTheirOrganisationsWebsite(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{
		Mode: asset.EnrollmentInvite, MembershipSource: "roster_the_website",
	})
	h := aPersonsIdentityAgent(t)
	req := w.challenge(t)

	preview, err := h.Preview(req)
	if err != nil {
		t.Fatalf("the person's Identity Agent refused the organisation's own website: %v", err)
	}
	if preview.RelationshipAnchorAID == "" {
		t.Fatal("the sign-in was not anchored to the organisation, so it would not present the enrolled identity")
	}
	w.roster[preview.PairwiseAID] = true

	if _, err := h.Approve(req); err != nil {
		t.Fatalf("a member's approved sign-in was not admitted: %v", err)
	}
	w.org.challengeMu.Lock()
	status := w.org.challengeStatus[req.SessionToken]["status"]
	w.org.challengeMu.Unlock()
	if status != "complete" {
		t.Fatalf("the organisation's sign-in session is %v, not complete", status)
	}
}

// The same chain into an invite-only website that has invited nobody. Every
// check of keys and approval passes, and the organisation refuses on its
// policy alone.
func TestSomebodyNotInvitedIsRefusedOnPolicyAlone(t *testing.T) {
	w := anOrganisationWithAWebsite(t, asset.EnrollmentPolicy{Mode: asset.EnrollmentInvite})
	h := aPersonsIdentityAgent(t)
	req := w.challenge(t)

	if _, err := h.Preview(req); err != nil {
		t.Fatalf("the person's Identity Agent refused a genuine website: %v", err)
	}
	_, err := h.Approve(req)
	if err == nil {
		t.Fatal("somebody nobody invited was signed in")
	}
	// The policy refusal is deliberately opaque to the person (it says only
	// "not authorized"); a key or signature failure says what failed.
	if !strings.Contains(err.Error(), "403: not authorized") {
		t.Fatalf("refused, but not for the policy: %v", err)
	}
}
