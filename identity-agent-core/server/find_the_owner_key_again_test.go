package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/store"
)

// Recovering the key to a machine when only the recovery words survive.
//
// The words re-derive the root seed; nothing in them says which index a
// machine's owner identity came from. That index lived only on the device that
// minted it and in its backup archive — so an archive lost meant a machine that
// could never be spoken to again.

// aMachineAnsweringTo stands in for a paired machine, serving the one thing
// this needs: which identity it answers to, and the key.
func aMachineAnsweringTo(t *testing.T, aid, publicKey string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/api/owners/authority") {
			http.NotFound(w, r)
			return
		}
		if aid == "" {
			json.NewEncoder(w).Encode(map[string]any{"owner": nil})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"owner": map[string]string{"aid": aid, "public_key": publicKey},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func recoverFrom(t *testing.T, s *CoreServer, url string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/machines/recover-owner",
		strings.NewReader(`{"machine_url":"`+url+`"}`))
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	s.handleRecoverMachineOwner(rec, req)
	return rec
}

// THE POINT. A device with the seed and no record of the index finds it again.
func TestTheIndexIsFoundAgainFromTheSeedAlone(t *testing.T) {
	s := adoptingOwner(t)

	// Mint an owner the way pairing does, then forget where it came from —
	// which is exactly the state a device restored from the words is in.
	rec := httptest.NewRecorder()
	s.handleMintMachineOwner(rec, httptest.NewRequest(http.MethodPost, "/api/machines/owner-identity", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("could not mint: %s", rec.Body.String())
	}
	var minted struct {
		AID string `json:"aid"`
	}
	json.NewDecoder(rec.Body).Decode(&minted)

	idx, known, err := s.DataStore.MachineOwnerIndex(minted.AID)
	if err != nil || !known {
		t.Fatalf("the mint recorded no index: %v", err)
	}
	key, err := s.pairwisePublicKey(idx)
	if err != nil {
		t.Fatal(err)
	}

	machine := aMachineAnsweringTo(t, minted.AID, key)

	got := recoverFrom(t, s, machine.URL)
	if got.Code != http.StatusOK {
		t.Fatalf("the index was not found again: %d %s", got.Code, got.Body.String())
	}
	var out recoverOwnerResponse
	json.NewDecoder(got.Body).Decode(&out)
	if out.Index != idx {
		t.Fatalf("found index %d, the machine's owner is at %d", out.Index, idx)
	}

	// And written down, so this is a one-off rather than a search every time.
	again, known, err := s.DataStore.MachineOwnerIndex(minted.AID)
	if err != nil || !known || again != idx {
		t.Errorf("the recovered index was not recorded: %d known=%v err=%v", again, known, err)
	}
}

// Somebody else's machine is not found, however long the search.
//
// The search proves nothing by itself — it recovers an ability this device
// always had. A device with different words derives different keys and matches
// nothing, and must be told so rather than left waiting.
func TestAMachineThisDeviceNeverMintedIsNotFound(t *testing.T) {
	s := adoptingOwner(t)
	machine := aMachineAnsweringTo(t, "ESomebodyElsesMachineOwner",
		"DAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH")

	got := recoverFrom(t, s, machine.URL)
	if got.Code != http.StatusNotFound {
		t.Fatalf("a machine this device never minted was claimed as found: %d %s",
			got.Code, got.Body.String())
	}
	if !strings.Contains(got.Body.String(), "recovery words") {
		t.Errorf("refused without saying the likely reason: %s", got.Body.String())
	}
}

// A machine nobody has claimed says so, rather than being searched for.
func TestAnUnclaimedMachineIsNotSearchedFor(t *testing.T) {
	s := adoptingOwner(t)
	machine := aMachineAnsweringTo(t, "", "")

	got := recoverFrom(t, s, machine.URL)
	if got.Code == http.StatusOK {
		t.Fatal("a machine that answers to nobody was reported as recovered")
	}
}

// The pool bases have ONE definition.
//
// Two would drift, and the failure is silent: a pool allocated from one base
// and searched from another finds nothing and reports a machine as belonging to
// somebody else.
func TestTheSearchStartsWhereTheMintingStarts(t *testing.T) {
	base, err := store.PoolBase("machines")
	if err != nil {
		t.Fatal(err)
	}
	s := adoptingOwner(t)
	rec := httptest.NewRecorder()
	s.handleMintMachineOwner(rec, httptest.NewRequest(http.MethodPost, "/api/machines/owner-identity", nil))
	var minted struct {
		AID string `json:"aid"`
	}
	json.NewDecoder(rec.Body).Decode(&minted)

	idx, _, _ := s.DataStore.MachineOwnerIndex(minted.AID)
	if idx < base {
		t.Fatalf("minted at %d, below the base the search starts from (%d) — the search "+
			"would never reach it", idx, base)
	}
	if idx >= base+ownerSearchLimit {
		t.Fatalf("minted at %d, beyond where the search stops (%d)", idx, base+ownerSearchLimit)
	}
}
