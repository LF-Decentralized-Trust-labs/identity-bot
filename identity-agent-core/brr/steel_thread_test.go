package brr_test

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"identity-agent-core/brr"
)

// newFakeBRR is a minimal in-process stand-in for the BRR service, sufficient to
// exercise the IA-side client steel thread. It records the latest event per
// blinded id and serves a bulk proof listing currently-revoked ids.
//
// This replaces the cross-repo brrtest helper so identity-agent-core builds
// without any external service or cross-repo dependency — required for the
// gomobile/CI builds (a local `replace` to a missing dir breaks module loading).
func newFakeBRR(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	type latest struct {
		seq     int
		revoked bool
	}
	state := map[string]latest{}

	mux := http.NewServeMux()
	mux.HandleFunc("/registry/enroll", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/registry/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/event"):
			var req brr.EventRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			if cur := state[req.BlindedID]; req.SequenceNumber >= cur.seq {
				state[req.BlindedID] = latest{seq: req.SequenceNumber, revoked: req.EventType == "rev"}
			}
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/bulk-proof"):
			prefix := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/registry/"), "/bulk-proof")
			mu.Lock()
			var revoked []string
			for id, s := range state {
				if s.revoked {
					revoked = append(revoked, id)
				}
			}
			mu.Unlock()
			resp := map[string]interface{}{
				"proof": brr.BulkProof{
					RegistryPrefix: prefix,
					// Non-empty roots: VerifyLocally requires them present; full
					// sparse-merkle composition is a separate (BLOCKED) path.
					MerkleRoot:  "11" + strings.Repeat("0", 62),
					SubtreeRoot: "22" + strings.Repeat("0", 62),
					RevokedIDs:  revoked,
				},
				"brr_signature": "",
				"signed_by":     "",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return httptest.NewServer(mux)
}

// Steel thread: issue → blind-revoke → verifier detects revocation without contacting issuer.
func TestSteelThreadIssueBlindRevokeVerify(t *testing.T) {
	ts := newFakeBRR(t)
	defer ts.Close()

	_, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := brr.NewClient(ts.URL, issuerPriv)

	registryPrefix := "ERegM36Steel"
	credentialSAID := "EAcredM36SteelThread000000000000000001"
	registrySalt := "private-acdc-registry-salt-7f3a"

	if err := client.Enroll(registryPrefix); err != nil {
		t.Fatal(err)
	}

	blinded := brr.BlindedID(credentialSAID, registrySalt)
	if err := client.PushBlindedEvent(registryPrefix, blinded, "iss", 1); err != nil {
		t.Fatal(err)
	}

	status, err := brr.CheckRevocation(client, brr.VerifyInput{
		CredentialSAID: credentialSAID,
		RegistrySalt:   registrySalt,
		RegistryPrefix: registryPrefix,
		BRRBaseURL:     ts.URL,
	})
	if err != nil || status != brr.StatusValid {
		t.Fatalf("pre-revoke: status=%s err=%v", status, err)
	}

	if err := client.PushBlindedEvent(registryPrefix, blinded, "rev", 2); err != nil {
		t.Fatal(err)
	}

	status, err = brr.CheckRevocation(client, brr.VerifyInput{
		CredentialSAID: credentialSAID,
		RegistrySalt:   registrySalt,
		RegistryPrefix: registryPrefix,
		BRRBaseURL:     ts.URL,
	})
	if err != nil || status != brr.StatusRevoked {
		t.Fatalf("post-revoke: status=%s err=%v", status, err)
	}
}
