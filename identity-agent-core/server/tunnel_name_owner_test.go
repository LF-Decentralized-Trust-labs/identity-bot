package server

import (
	"identity-agent-core/endpoint"
	"testing"

	"encoding/base64"
	keri "github.com/grapeid/keri-go"
)

// The identity that owns a tunnel name is the same one at every start, because
// the hub reconnects a name only for the key that claimed it; and the key log it
// presents verifies as that identity's.
func TestATunnelNameHasTheSameOwnerAtEveryStart(t *testing.T) {
	s, _ := grantWorld(t)
	s.EndpointService = endpoint.New(nil, 5050)
	first, err := s.tunnelNameOwner("grapeid.org")
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.tunnelNameOwner("grapeid.org")
	if err != nil {
		t.Fatal(err)
	}
	if again.AID != first.AID || again.PublicKeyB64 != first.PublicKeyB64 {
		t.Fatalf("a second start presented a different owner: %s then %s", first.AID, again.AID)
	}
	stream, _ := base64.StdEncoding.DecodeString(again.KELCESRB64)
	messages, err := keri.ParseKELStream(stream)
	if err != nil {
		t.Fatal(err)
	}
	state, err := keri.ValidateSignedKEL(messages)
	if err != nil || state.Identifier != first.AID {
		t.Fatalf("the owner's key log does not establish it: %v %v", err, state)
	}
}
