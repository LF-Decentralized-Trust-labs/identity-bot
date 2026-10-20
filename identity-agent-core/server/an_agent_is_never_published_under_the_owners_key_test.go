package server

import (
	"errors"
	"net/http/httptest"
	"testing"
)

// A key that cannot be found for an identity is an error. It is never filled in
// with the owner's key, which would publish a document claiming the owner's key
// controls an identity it does not.
func TestAnIdentityWithNoKnownKeyIsNotPublishedUnderTheOwnersKey(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	owner, err := s.DataStore.GetIdentity()
	if err != nil || owner == nil {
		t.Fatalf("the test agent has no owner identity: %v", err)
	}

	in, err := s.publisherInput(httptest.NewRequest("GET", "/x", nil), "EANAGENTNOBODYKNOWS")
	if err == nil {
		t.Fatalf("an identity with no known key was published, with key %q", in.PublicKeyB64)
	}
	if in.PublicKeyB64 == owner.PublicKey {
		t.Fatal("an identity with no known key was published under the owner's key")
	}
	if errors.Is(err, errNotPublishable) {
		t.Fatalf("refused as the owner's own identity, which it is not: %v", err)
	}
}
