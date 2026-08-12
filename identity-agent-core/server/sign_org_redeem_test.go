package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// What a person's agent actually sends when they agree to own an organisation.
//
// This is the one request the whole founding hangs on, and it was missing the
// two fields the organisation refuses without. The failure was invisible from
// both ends: the person's agent reported that it had signed, the organisation
// answered 400 to a call nobody watched, and its screen went on waiting for an
// owner who had already agreed. Nothing said the two were talking past each
// other.

// captureRedeem stands in for the organisation, recording the redeem body and
// answering the way the real handler does.
func captureRedeem(t *testing.T, got *map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/redeem") {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(got); err != nil {
			t.Errorf("the organisation could not read the redeem: %v", err)
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "accepted"})
	}))
}

// The real handler's own rule, asserted here so this test fails if that rule
// ever moves: an organisation refuses an owner it cannot verify.
func TestAnOrganisationStillRefusesAnOwnerItCannotVerify(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/signer/invites/tok/redeem",
		strings.NewReader(`{"pairwise_aid":"ESIGNER","vouch_sig":"sig"}`))
	s.handleRedeemSignerInvite(w, r)

	if w.Code == http.StatusOK {
		t.Fatal("an organisation accepted an owner whose signature it could not check")
	}
	if !strings.Contains(w.Body.String(), "public_key") {
		t.Fatalf("the refusal does not name what is missing: %s", w.Body)
	}
}

// And the half that was broken: what the signer's agent puts in that request.
func TestSigningForAnOrganisationSendsWhatItRefusesWithout(t *testing.T) {
	body := map[string]string{}
	org := captureRedeem(t, &body)
	defer org.Close()

	s := agentWithDerivedIdentity(t)
	// The relationship this signs under is derived by the login engine, so the
	// action genuinely needs it — the same dependency the real path has.
	if err := s.initLoginHandler(); err != nil {
		t.Skipf("login engine unavailable: %v", err)
	}
	if err := signOrgRedeemFor(t, s, org.URL); err != nil {
		t.Fatalf("signing for the organisation failed: %v", err)
	}

	// THE POINT. Without these the organisation answers 400 and the founding
	// never completes, however correct everything either side did.
	if body["public_key"] == "" {
		t.Error("no public key was sent, so the organisation cannot verify its own owner " +
			"and refuses the request outright")
	}
	if body["next_public_key"] == "" {
		t.Error("no rotation key was sent, so this owner could never be replaced — which is " +
			"the one thing founding an organisation as its own root exists to keep possible")
	}
	// And the recovery key, which decides whether the organisation can ever be
	// restored after losing the machine it runs on.
	if body["backup_seal_public_key_b64"] == "" {
		t.Error("no recovery key was sent, so this organisation can write no backup anybody " +
			"could restore, and on rented hardware has no way back into its own disk")
	}

	// The vouch is signed with the same key that was handed over, or the
	// organisation would be verifying one key against another.
	if body["pairwise_aid"] == "" || body["vouch_sig"] == "" {
		t.Error("the vouch itself is incomplete")
	}
}

// signOrgRedeemFor runs the sign_org action the way a scan does: an approved
// decision over an Ask naming an organisation, against the URL that stands in
// for it.
func signOrgRedeemFor(t *testing.T, s *CoreServer, orgURL string) error {
	t.Helper()
	ask, _ := json.Marshal(signerPayload{
		OrgName:     "Test Organisation",
		OrgAID:      "EORGAID",
		SiteAID:     "EORGAID",
		InviteToken: "tok",
	})
	_, err := addSignerAsk{}.Execute(s, AskContext{
		Base:     orgURL,
		Token:    "tok",
		AskBytes: ask,
		T:        4,
	}, ScanDecision{Approved: true})
	return err
}
