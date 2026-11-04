package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/drivers/driverfake"
	"identity-agent-core/store"
)

// Resolving a contact's address must not call a history verified when the check
// names no key it ends on: the only key left is the one the peer served beside
// the log, which nothing checked.
func TestResolvingAContactWhoseCheckedHistoryNamesNoKeyDoesNotVerifyIt(t *testing.T) {
	for _, tc := range []struct {
		name         string
		key          string
		wantVerified bool
	}{
		{"the check names the key the log ends on", "DCheckedKey", true},
		{"the check names no key", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const peer = "EPeerResolvedByAddress"
			s := witnessWithSeed(t, 1)
			verdict := &drivers.DriverValidateKELResponse{KelVerified: true, CurrentPublicKey: tc.key}
			s.KeriDriver = &driverfake.Engine{
				ValidateKELFunc: func(string, []map[string]interface{}) (*drivers.DriverValidateKELResponse, error) {
					return verdict, nil
				},
				ValidateKELBytesFunc: func(drivers.ValidateKELInput) (*drivers.DriverValidateKELResponse, error) {
					return verdict, nil
				},
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"aid": peer, "public_key": "DServedKeyNobodyChecked", "alias": "peer",
					"kel": withTheBytesItWasVerifiedBy(t, map[string]interface{}{"t": "icp", "s": "0", "i": peer, "d": peer}),
				})
			}))
			t.Cleanup(srv.Close)

			body, _ := json.Marshal(map[string]string{"oobi_url": srv.URL + "/oobi/" + peer})
			rec := httptest.NewRecorder()
			s.handleResolveOobiContact(rec, httptest.NewRequest(http.MethodPost, "/api/contacts/resolve", bytes.NewReader(body)))
			if rec.Code != http.StatusOK {
				t.Fatalf("resolve: %d %s", rec.Code, rec.Body.String())
			}
			var got struct {
				KelVerified bool `json:"kel_verified"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.KelVerified != tc.wantVerified {
				t.Fatalf("kel_verified = %v, want %v", got.KelVerified, tc.wantVerified)
			}
			kel, _ := s.DataStore.GetContactKEL(peer)
			if kel == nil || kel.KelVerified != tc.wantVerified {
				t.Fatalf("stored log verified = %+v, want %v", kel, tc.wantVerified)
			}
		})
	}
}

// A credential is checked against its issuer's stored log only if that log is a
// verified one, on both verification routes. The driver sees no issuer log
// otherwise; with a verified one it sees it, so the test is not vacuous.
func TestTheVerifyRoutesGiveTheDriverOnlyAVerifiedIssuerLog(t *testing.T) {
	const issuer = "EIssuerOfThePresentedCredential"
	acdc := base64Of(`{"i":"` + issuer + `","d":"ESaid","s":"ESchema"}`)
	routes := map[string]struct {
		call func(s *CoreServer, w http.ResponseWriter, r *http.Request)
		body map[string]any
	}{
		"credential/verify":  {func(s *CoreServer, w http.ResponseWriter, r *http.Request) { s.handleVerifyCredential(w, r) }, map[string]any{"acdc_json": acdc}},
		"credentials/verify": {func(s *CoreServer, w http.ResponseWriter, r *http.Request) { s.handleVerifyCredentialChain(w, r) }, map[string]any{"acdc_json_b64": acdc}},
	}
	for name, route := range routes {
		for _, verified := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s verified=%v", name, verified), func(t *testing.T) {
				s := witnessWithSeed(t, 1)
				var seen []map[string]interface{}
				s.KeriDriver = &driverfake.Engine{
					VerifyCredentialFunc: func(req *drivers.DriverVerifyCredentialRequest) (*drivers.DriverVerifyCredentialResponse, error) {
						seen = req.IssuerKelEvents
						return &drivers.DriverVerifyCredentialResponse{Verified: true}, nil
					},
				}
				if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{
					AID: issuer, KelVerified: verified,
					KEL: withTheBytesItWasVerifiedBy(t, map[string]interface{}{"t": "icp", "s": "0", "i": issuer, "d": issuer}),
				}); err != nil {
					t.Fatal(err)
				}
				raw, _ := json.Marshal(route.body)
				rec := httptest.NewRecorder()
				route.call(s, rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw)))
				if verified && len(seen) == 0 {
					t.Fatalf("a verified issuer log was not given to the driver (%d %s)", rec.Code, rec.Body.String())
				}
				if !verified && seen != nil {
					t.Fatalf("an unverified issuer log was given to the driver: %v", seen)
				}
			})
		}
	}
}
