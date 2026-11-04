package relayproto

import (
	"context"
	"testing"
)

// An Identity Agent is told it is admitted only once the relay has the session
// registered: whatever it asks the relay next (binding an address) is answered
// by a relay that already knows it. Told earlier, that first request could
// arrive in between and be refused as coming from nobody.
func TestAnAdmittedSessionIsAlreadyRegistered(t *testing.T) {
	r := newRelay(t, nil)
	for i := 0; i < 200; i++ {
		id := newIdentity(t)
		a, err := Dial(context.Background(), r.agentConfig(id))
		if err != nil {
			t.Fatal(err)
		}
		_, ok := r.registry.Get(id.aid)
		a.Close()
		if !ok {
			t.Fatalf("admission %d: the Identity Agent was told it is admitted before the relay held its session", i)
		}
	}
}
