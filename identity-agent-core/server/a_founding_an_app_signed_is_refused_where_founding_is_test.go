package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/keriengine"
	"identity-agent-core/recovery"

	keri "github.com/grapeid/keri-go"
)

// anAppSignedFounding is a founding signed by its own key, as an app sends it.
func anAppSignedFounding(t *testing.T) (raw []byte, sig string) {
	t.Helper()
	seed, next := make([]byte, 32), make([]byte, 32)
	for i := range seed {
		seed[i], next[i] = byte(i+40), byte(i+80)
	}
	raw, err := keri.BuildInception(keri.InceptionInput{Keys: []string{verkeyOf(seed)},
		NextDigests: []string{digestOfSeed(t, next)}, Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	if sig, err = signEventBytes(raw, seed); err != nil {
		t.Fatal(err)
	}
	return raw, sig
}

// A founding signed somewhere else is still a founding here: committing it,
// installing it as a restored identity, or making it the new root of a
// break-glass rotation is refused on a machine that may not found one.
func TestAFoundingAnAppSignedIsRefusedWhereFoundingIs(t *testing.T) {
	raw, sig := anAppSignedFounding(t)
	ev, _ := keri.ParseEvent(raw)
	signed := drivers.SignedEventBytes{RawB64: base64.StdEncoding.EncodeToString(raw), Sigs: []string{sig}}

	for _, door := range []struct {
		what string
		path string
		body any
		call func(*CoreServer, http.ResponseWriter, *http.Request)
	}{
		{"committing a founding", "/api/events/commit", signed, (*CoreServer).handleCommitEvent},
		{"installing a restored identity", "/api/identity/restore",
			map[string]any{"aid": ev.Identifier, "events": []drivers.SignedEventBytes{signed}},
			(*CoreServer).handleRestoreIdentity},
	} {
		t.Run(door.what, func(t *testing.T) {
			s := agentWithNoIdentity(t)
			s.KeriDriver = keriengine.New()
			refuseFoundingHere(t)
			body, _ := json.Marshal(door.body)
			req := httptest.NewRequest(http.MethodPost, door.path, strings.NewReader(string(body)))
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
			rec := httptest.NewRecorder()
			door.call(s, rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s is not refused on a computer that cannot prove its software: %d %s",
					door.what, rec.Code, rec.Body.String())
			}
			if got, _ := s.DataStore.GetIdentity(); got != nil {
				t.Fatalf("%s was refused and still left an identity: %s", door.what, got.AID)
			}
		})
	}

	t.Run("the new root of a break-glass rotation", func(t *testing.T) {
		s := agentWithNoIdentity(t)
		s.KeriDriver = keriengine.New()
		refuseFoundingHere(t)
		rec := httptest.NewRecorder()
		if _, ok := s.theNewRootMayBeFounded(rec, recovery.RootAIDRotationRequest{NewRootFounding: signed}); ok {
			t.Fatal("a new root was let through on a computer that cannot prove its software")
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("the refusal was answered %d %s", rec.Code, rec.Body.String())
		}
	})
}
