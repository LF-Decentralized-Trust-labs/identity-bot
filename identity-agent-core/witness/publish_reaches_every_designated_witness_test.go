package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sort"
	"strings"
	"sync"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
)

// designatedOnly sets up a root identity whose key log designates three
// witnesses that are NOT witness contacts, so enrolledWitnesses gives nothing
// for it: the only way a publication reaches them is through the key log's own
// designation. It returns the root AID, the designated keys, and a recorder of
// the hosts that were posted to.
func designatedOnly(t *testing.T) (s *Service, root string, keys []string, posted func() []string) {
	t.Helper()
	s, mc := testService(t)
	root = mc.identity.AID
	was := BootstrapWitnesses
	BootstrapWitnesses = nil // no bootstrap top-up may stand in for the designation
	t.Cleanup(func() { BootstrapWitnesses = was })

	for _, host := range []string{"w1", "w2", "w3"} {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		key := iacrypto.NonTransferableAIDQB64(pub)
		aid := "EContact" + host
		mc.contacts[aid] = store.ContactRecord{AID: aid, OobiURL: "http://" + host + ".test"}
		_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: aid, WitnessKey: key})
		keys = append(keys, key)
	}
	s.DesignationAfter = func(string, map[string]interface{}) ([]string, int, error) { return keys, 2, nil }

	var mu sync.Mutex
	hosts := map[string]bool{}
	s.PostEvent = func(_ context.Context, url string, _ []byte) (map[string]interface{}, error) {
		h := strings.SplitN(strings.TrimPrefix(url, "http://"), ".", 2)[0]
		mu.Lock()
		hosts[h] = true
		mu.Unlock()
		return map[string]interface{}{}, nil
	}
	posted = func() []string {
		mu.Lock()
		defer mu.Unlock()
		var out []string
		for h := range hosts {
			out = append(out, h)
		}
		sort.Strings(out)
		return out
	}
	return s, root, keys, posted
}

// A changed address is published to every witness the identity's key log
// designates, not only to the ones a NEW identity would be given.
func TestAnEndpointRecordReachesEveryDesignatedWitness(t *testing.T) {
	s, root, _, posted := designatedOnly(t)
	if err := s.PublishEndpointRecord(context.Background(), root, map[string]interface{}{"url": "https://me.test"}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(posted(), ","); got != "w1,w2,w3" {
		t.Fatalf("the endpoint record reached %q, want every designated witness w1,w2,w3", got)
	}
}

// Registry events are sent to every witness the key log designates, and the
// count of witnesses holding them is all three.
func TestRegistryEventsReachEveryDesignatedWitness(t *testing.T) {
	s, root, keys, posted := designatedOnly(t)
	held, err := s.PublishTEL(context.Background(), root, [][]byte{[]byte(`{"t":"iss"}`)}, keys)
	if err != nil {
		t.Fatal(err)
	}
	if held != 3 {
		t.Fatalf("%d designated witnesses hold the events, want 3", held)
	}
	if got := strings.Join(posted(), ","); got != "w1,w2,w3" {
		t.Fatalf("registry events reached %q, want every designated witness w1,w2,w3", got)
	}
}
