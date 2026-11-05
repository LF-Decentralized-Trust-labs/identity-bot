package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	keri "github.com/grapeid/keri-go"
	"net/http"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/drivers/driverfake"
	"identity-agent-core/store"
)

// A checked history that names no key the log ends on is not a verified one:
// the only key left would be the one the peer served beside it, which nothing
// checked. Adding the contact must leave it unverified.
func TestAContactWhoseCheckedHistoryNamesNoKeyIsNotVerified(t *testing.T) {
	a := startOwnerPeer(t, "EAgentA0000000000000000000000000000000000001")
	b := startOwnerPeer(t, "EAgentB0000000000000000000000000000000000002")
	ownerPeerKeys.Store(b.aid, "") // the driver says verified, and names no key

	resp := postJSON(t, a.base+"/api/contacts", map[string]any{"oobi_url": b.oobi(), "trusted": true})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add-contact: %d", resp.StatusCode)
	}
	kel, _ := a.core.DataStore.GetContactKEL(b.aid)
	if kel != nil && kel.KelVerified {
		t.Fatalf("a history with no key it ends on was kept as verified: %+v", kel)
	}
	rec, _ := a.core.DataStore.GetContact(b.aid)
	if rec == nil || rec.Status == "verified" || rec.Status == "accepted" {
		t.Fatalf("the contact was treated as checked: %+v", rec)
	}
}

// A presented credential is checked against its issuer's log only if that log
// is a verified one. A stored log that is not verified is not a source of the
// issuer's keys, whatever its served text says.
func TestACredentialIsNotCheckedAgainstAnUnverifiedIssuerLog(t *testing.T) {
	s := witnessWithSeed(t, 1)
	const issuer = "EIssuerWhoseLogWasNeverVerified"
	called := false
	s.KeriDriver = &driverfake.Engine{
		VerifyCredentialFunc: func(*drivers.DriverVerifyCredentialRequest) (*drivers.DriverVerifyCredentialResponse, error) {
			called = true
			return &drivers.DriverVerifyCredentialResponse{Verified: true}, nil
		},
	}
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: issuer, KelVerified: false,
		KEL: withTheBytesItWasVerifiedBy(t, map[string]interface{}{"t": "icp", "s": "0", "i": issuer, "d": issuer}),
	}); err != nil {
		t.Fatal(err)
	}
	acdc := aRealCredentialFrom(t, issuer)
	ok, _, reason := s.verifyPresentedCredentialACDC(context.Background(), acdc, "EHolder", "", "", "", nil)
	if ok || called {
		t.Fatalf("a credential was checked against an unverified issuer log (ok=%v, driver called=%v)", ok, called)
	}
	if reason != "issuer KEL not found" {
		t.Fatalf("unexpected reason: %q", reason)
	}
}

func base64Of(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// aRealCredentialFrom is a well-formed credential, its identifier correct, that
// names issuer as its issuer. The server reads every credential it verifies
// the way the engine does, so a fixture that is not one is refused unread.
func aRealCredentialFrom(t *testing.T, issuer string) string {
	t.Helper()
	acdc, err := keri.BuildCredential(keri.CredentialInput{
		SchemaSAID: "ESchema", Issuer: issuer, Recipient: "EHolder",
		Data: json.RawMessage(`{"d":"","i":"EHolder","dt":"2026-01-01T00:00:00.000000+00:00"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(acdc)
}
