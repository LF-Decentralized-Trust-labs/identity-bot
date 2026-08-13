package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/endpoint"
	"identity-agent-core/keriengine"
)

// Adopting a machine must not publish who the owner is.
//
// A delegated machine names its delegator inside its own inception event, and
// serves that event to anybody who can reach it. Delegating from the root
// therefore published the one identifier that identifies a person everywhere,
// to anyone who knew where their machine was — and bought nothing, because
// nothing fetches the delegator's log to check the anchor.
//
// So a machine founds its own root and names a PAIRWISE identity of this
// owner's as its owner. These tests are about that identity being pairwise, and
// about it being written down — an owner whose index was never recorded can
// never sign to that machine again.

// adoptingMachine stands in for a black box: it offers key material and records
// what it is asked to become.
func adoptingMachine(t *testing.T, got *pairingCompleteRequest) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/pairing/begin"):
			json.NewEncoder(w).Encode(pairingBeginResponse{
				PairwiseAID:   "EBOXPAIRWISE",
				PublicKey:     "DBOXKEY",
				NextPublicKey: "DBOXNEXTKEY",
			})
		case strings.HasSuffix(r.URL.Path, "/api/pairing/complete"):
			if err := json.NewDecoder(r.Body).Decode(got); err != nil {
				t.Errorf("the machine could not read what it was sent: %v", err)
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true, "root_aid": "EMACHINEOWNROOT",
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

// adoptingOwner is an agent that can mint identities — adoption derives a
// pairwise identity for the machine, so the engine is genuinely needed.
func adoptingOwner(t *testing.T) *CoreServer {
	t.Helper()
	s := agentWithDerivedIdentity(t)
	eng := keriengine.New()
	if err := eng.Start(); err != nil {
		t.Skipf("KERI engine unavailable: %v", err)
	}
	s.KeriDriver = eng
	// Minting an identity composes an OOBI from the public URL, so the service
	// has to exist even though nothing here is reachable.
	s.EndpointService = endpoint.New(nil, 0)
	return s
}

func adoptFrom(t *testing.T, s *CoreServer, url string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"box_url":"` + url + `","adoption_code":"code","allow_unattested":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/adopt", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	s.handlePairingAdopt(rec, req)
	return rec
}

// THE POINT OF THE WHOLE CHANGE.
func TestAdoptingAMachineNeverNamesTheRootIdentity(t *testing.T) {
	s := adoptingOwner(t)
	root, err := s.DataStore.GetIdentity()
	if err != nil || root == nil {
		t.Fatal("fixture has no identity")
	}

	var sent pairingCompleteRequest
	box := adoptingMachine(t, &sent)
	defer box.Close()

	if rec := adoptFrom(t, s, box.URL); rec.Code != http.StatusOK {
		t.Fatalf("adoption failed: %d %s", rec.Code, rec.Body.String())
	}

	// The machine publishes what it is told here. If the root appears in any of
	// it, the machine's own event names the person for anybody to read.
	if sent.OwnerAID == root.AID {
		t.Fatal("the machine was told its owner is the ROOT identity, so its own " +
			"published event names the identifier that identifies this person " +
			"everywhere — to anyone who can reach the machine")
	}
	if sent.DelegatorAID == root.AID {
		t.Error("the root was named as delegator")
	}
	if sent.OwnerAID == "" {
		t.Fatal("no owner at all, so whoever reaches the machine first becomes its owner")
	}

	// Founded, not delegated: no delegation is issued, so there is nothing
	// naming a parent in the machine's inception.
	if !sent.FoundAsRoot {
		t.Error("the machine was asked to be a delegate rather than to found its own root")
	}
	if sent.DipEvent != nil {
		t.Error("a delegated inception was sent, which names its delegator for ever")
	}
}

// The owner identity is useless unless we can find its key again.
func TestAnAdoptedMachineRecordsWhichIdentityOwnsIt(t *testing.T) {
	s := adoptingOwner(t)

	var sent pairingCompleteRequest
	box := adoptingMachine(t, &sent)
	defer box.Close()

	if rec := adoptFrom(t, s, box.URL); rec.Code != http.StatusOK {
		t.Fatalf("adoption failed: %d %s", rec.Code, rec.Body.String())
	}

	agents, err := s.DataStore.ListAdoptedAgents()
	if err != nil || len(agents) != 1 {
		t.Fatalf("expected one adopted machine, got %d (%v)", len(agents), err)
	}
	got := agents[0]

	if got.OwnerAID != sent.OwnerAID {
		t.Errorf("recorded owner %q but told the machine %q — the two must agree or "+
			"we cannot speak to our own machine", got.OwnerAID, sent.OwnerAID)
	}
	if got.OwnerIndex == 0 {
		t.Fatal("no derivation index recorded, so this owner identity can never be " +
			"re-derived: no signing to this machine again, no rotation, no revocation")
	}
	// And the key that identity presents must be the one that index produces,
	// or the machine will refuse every signature we make.
	key, err := s.pairwisePublicKey(got.OwnerIndex)
	if err != nil {
		t.Fatalf("could not re-derive the owner key: %v", err)
	}
	if key != sent.OwnerPublicKey {
		t.Fatal("the key re-derived from the stored index is not the key the machine " +
			"was given, so every request we sign to it would be refused")
	}
}

// Two machines must not share an owner identity, or one operator seeing both
// learns they belong to the same person.
func TestEachMachineGetsItsOwnOwnerIdentity(t *testing.T) {
	s := adoptingOwner(t)

	var first, second pairingCompleteRequest
	boxA := adoptingMachine(t, &first)
	defer boxA.Close()
	boxB := adoptingMachine(t, &second)
	defer boxB.Close()

	if rec := adoptFrom(t, s, boxA.URL); rec.Code != http.StatusOK {
		t.Fatalf("first adoption failed: %s", rec.Body.String())
	}
	if rec := adoptFrom(t, s, boxB.URL); rec.Code != http.StatusOK {
		t.Fatalf("second adoption failed: %s", rec.Body.String())
	}

	if first.OwnerAID == second.OwnerAID {
		t.Fatal("both machines were given the same owner identity, so anybody who " +
			"sees both knows they belong to one person")
	}
}

// The identity has to exist BEFORE the machine is asked for, because the
// machine is told who may claim it before it starts. So adoption must be able
// to use one that was minted earlier — and must refuse one it never minted.
func TestAdoptionUsesTheIdentityMintedBeforeTheMachineExisted(t *testing.T) {
	s := adoptingOwner(t)

	rec := httptest.NewRecorder()
	s.handleMintMachineOwner(rec, httptest.NewRequest(http.MethodPost, "/api/machines/owner-identity", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("minting failed: %d %s", rec.Code, rec.Body.String())
	}
	var minted struct {
		AID string `json:"aid"`
	}
	json.NewDecoder(rec.Body).Decode(&minted)
	if minted.AID == "" {
		t.Fatal("no identity minted, so nothing could be told to the provisioning host")
	}

	var sent pairingCompleteRequest
	box := adoptingMachine(t, &sent)
	defer box.Close()

	body := `{"box_url":"` + box.URL + `","adoption_code":"code","allow_unattested":true,"owner_aid":"` + minted.AID + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/adopt", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	got := httptest.NewRecorder()
	s.handlePairingAdopt(got, req)
	if got.Code != http.StatusOK {
		t.Fatalf("adoption failed: %d %s", got.Code, got.Body.String())
	}

	if sent.OwnerAID != minted.AID {
		t.Fatalf("the machine was told %q owns it, but the provisioning host was told %q — "+
			"the machine would refuse its own owner", sent.OwnerAID, minted.AID)
	}
}

// An identity this device never minted has no key here, so a machine adopted
// under it would answer to nobody.
func TestAdoptionRefusesAnOwnerIdentityItNeverMinted(t *testing.T) {
	s := adoptingOwner(t)

	var sent pairingCompleteRequest
	box := adoptingMachine(t, &sent)
	defer box.Close()

	body := `{"box_url":"` + box.URL + `","adoption_code":"code","allow_unattested":true,"owner_aid":"ESOMETHINGWEDIDNOTMINT"}`
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/adopt", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	got := httptest.NewRecorder()
	s.handlePairingAdopt(got, req)

	if got.Code == http.StatusOK {
		t.Fatal("a machine was adopted under an identity this device holds no key for, " +
			"so nobody could ever speak to it again")
	}
}
