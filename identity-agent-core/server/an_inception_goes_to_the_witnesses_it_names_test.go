package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/witness"
)

// A pairwise identity's inception is sent to exactly the witnesses it names.
// The witnesses to name were chosen on its key and the witnesses to send to
// again on its identifier, so with more than one witness to choose from it
// went, most of the time, to one it does not name.
func TestAPairwiseInceptionGoesToTheWitnessesItNames(t *testing.T) {
	var mu sync.Mutex
	got := map[string][]string{} // witness key -> identities sent to it
	var pool []witness.BootstrapWitness
	for i := byte(1); i <= 3; i++ {
		key := iacrypto.NonTransferableAIDQB64(bytes.Repeat([]byte{i}, 32))
		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(rw http.ResponseWriter, r *http.Request) {
			json.NewEncoder(rw).Encode(map[string]any{"service_aid": key})
		})
		mux.HandleFunc("/witness/event", func(rw http.ResponseWriter, r *http.Request) {
			var body struct {
				AID string `json:"aid"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			got[key] = append(got[key], body.AID)
			mu.Unlock()
			rw.WriteHeader(http.StatusBadRequest)
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		pool = append(pool, witness.BootstrapWitness{AID: key, WitnessKey: key, URL: srv.URL, Operator: "tests"})
	}
	prior := witness.BootstrapWitnesses
	witness.BootstrapWitnesses = func() []witness.BootstrapWitness { return pool }
	t.Cleanup(func() { witness.BootstrapWitnesses = prior })

	s := adoptingOwner(t)
	for n := 0; n < 6; n++ {
		aid, _, _, err := s.mintPairwise("check")
		if err != nil {
			t.Fatal(err)
		}
		events, _ := s.DataStore.GetEvents(aid)
		raw, _ := base64.StdEncoding.DecodeString(events[0].RawBytesB64)
		var icp struct {
			B []string `json:"b"`
		}
		json.Unmarshal(raw, &icp)
		if len(icp.B) == 0 {
			t.Fatal("the pairwise identity names no witness")
		}
		named := map[string]bool{}
		for _, b := range icp.B {
			named[b] = true
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			mu.Lock()
			reached := map[string]bool{}
			for key, aids := range got {
				for _, a := range aids {
					if a == aid {
						reached[key] = true
					}
				}
			}
			mu.Unlock()
			for key := range reached {
				if !named[key] {
					t.Fatalf("identity %d was sent to a witness it does not name", n)
				}
			}
			if len(reached) == len(named) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("identity %d reached %d of the %d witnesses it names", n, len(reached), len(named))
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}
