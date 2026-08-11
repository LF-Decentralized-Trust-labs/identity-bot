package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

// An owner reaching their own machine through the envelope, and everybody else
// failing to.
//
// The risk being tested is not the happy path. It is that the mechanism reads
// an ordinary HTTP header, so anything that trusts that header on a request the
// sealed transport did not replay is a complete authentication bypass — one
// curl away, against every owner-only route on the machine.

func ownerServer(t *testing.T, ownerAID string) *CoreServer {
	t.Helper()
	s := &CoreServer{DataDir: t.TempDir()}
	if ownerAID == "" {
		return s
	}
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if err := s.SealOwnerAuthority(OwnerAuthority{
		AID:       ownerAID,
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
	}); err != nil {
		t.Fatalf("sealing an owner: %v", err)
	}
	return s
}

func sealedReq(from string, remote string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/security/lineage", nil)
	r.RemoteAddr = remote
	if from != "" {
		r.Header.Set(headerSealedFrom, from)
	}
	return r
}

func TestTheOwnerIsRecognisedThroughTheEnvelope(t *testing.T) {
	const owner = "EOwnerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	s := ownerServer(t, owner)

	if !s.isOwner(sealedReq(owner, sealedRemoteAddr)) {
		t.Fatal("a request sealed by this machine's own owner was not treated as the owner, " +
			"which leaves an owner unable to ask their own machine anything")
	}
}

// THE ONE THAT MATTERS. Same header, same value, arriving on an ordinary
// connection rather than through the transport.
func TestAnAssertedHeaderAloneProvesNothing(t *testing.T) {
	const owner = "EOwnerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	s := ownerServer(t, owner)

	for _, remote := range []string{
		"203.0.113.9:44321", // somebody on the internet
		"127.0.0.1:5050",    // the tunnel client, which is where this is reached from
		"[::1]:5050",
		"", // no address at all
	} {
		if s.isSealedOwnerRequest(sealedReq(owner, remote)) {
			t.Fatalf("a caller claiming to be the owner in a header was believed, "+
				"on a request the sealed transport never replayed (remote %q). "+
				"Every owner-only route on this machine is then one curl away", remote)
		}
	}
}

func TestAnotherPeerIsNotTheOwner(t *testing.T) {
	const owner = "EOwnerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const stranger = "EStrangerBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	s := ownerServer(t, owner)

	// A registered peer can reach this machine — that is what being a peer is
	// for. It must not follow that they may act as its owner.
	if s.isSealedOwnerRequest(sealedReq(stranger, sealedRemoteAddr)) {
		t.Fatal("a peer that is not the owner was treated as the owner; being able to " +
			"talk to a machine is not permission to administer it")
	}
}

func TestAnUnadoptedMachineHasNoOwnerToImpersonate(t *testing.T) {
	s := ownerServer(t, "") // nobody has adopted it

	if s.isSealedOwnerRequest(sealedReq("EAnyoneAtAllCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", sealedRemoteAddr)) {
		t.Fatal("a machine with no owner accepted somebody as its owner")
	}
}

func TestAnEmptySenderIsNobody(t *testing.T) {
	const owner = "EOwnerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	s := ownerServer(t, owner)

	// Guards against an owner record whose AID is empty matching an envelope
	// that named no sender — two blanks agreeing is not a proof.
	if s.isSealedOwnerRequest(sealedReq("", sealedRemoteAddr)) {
		t.Fatal("a request naming no sender was treated as the owner")
	}
}
