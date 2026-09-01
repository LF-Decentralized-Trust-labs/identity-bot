package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Stands in for a machine that can prove its software, for the tests that are
// about something else and merely have to get past this.
func aMachineThatMayFound(t *testing.T) {
	t.Helper()
	was := mayFoundAnIdentityHere
	mayFoundAnIdentityHere = func() foundingVerdict {
		return foundingVerdict{Permitted: true, Platform: "test"}
	}
	t.Cleanup(func() { mayFoundAnIdentityHere = was })
}

// A machine that cannot prove its software is refused before it produces any.
//
// FOUNDING IS THE ONE ACT THAT CANNOT BE UNDONE. An identity's owner is fixed
// in the event that creates it, so one founded on a machine that cannot prove
// itself can never be moved to a machine that can — which is why this is
// checked before the request is even read, rather than somewhere further in.
//
// The gate that existed asked whether a key could be PROTECTED here. A Mac has
// a Secure Enclave, so it passed, and four root identities were founded on one.
// Protecting a key and proving what software is using it are different
// questions, and only the second is what somebody relying on an identity needs.
func TestAComputerThatCannotProveItsSoftwareMayNotFoundAnIdentity(t *testing.T) {
	s := agentWithNoIdentity(t)

	was := mayFoundAnIdentityHere
	mayFoundAnIdentityHere = func() foundingVerdict {
		return foundingVerdict{
			Permitted: false,
			Platform:  "macos",
			Why:       cannotProveItsSoftware,
			Instead:   actForOneInstead,
		}
	}
	t.Cleanup(func() { mayFoundAnIdentityHere = was })

	req := httptest.NewRequest(http.MethodPost, "/api/inception",
		strings.NewReader(`{"public_key":"D1","next_public_key":"D2"}`))
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	s.handleInception(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("a computer that cannot prove its software founded an identity: "+
			"%d %s", rec.Code, rec.Body.String())
	}
	// The refusal has to end somewhere. A person stopped from doing the obvious
	// thing, with no answer about what they can do instead, concludes the
	// software is broken — and the next thing they try is a way around it.
	if !strings.Contains(rec.Body.String(), "act for an identity") {
		t.Fatalf("the refusal does not say what this computer CAN do: %s",
			rec.Body.String())
	}
}

// And a machine that can prove itself is not stopped by this.
func TestAMachineThatCanProveItselfIsNotStopped(t *testing.T) {
	s := agentWithNoIdentity(t)
	aMachineThatMayFound(t)

	req := httptest.NewRequest(http.MethodPost, "/api/inception",
		strings.NewReader(`{"public_key":"D1","next_public_key":"D2"}`))
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	s.handleInception(rec, req)

	// It gets past THIS gate. What it hits next is the engine being absent in
	// this fixture, which is a different refusal and the point: 403 here would
	// mean the platform check fired on a machine that may found.
	if rec.Code == http.StatusForbidden {
		t.Fatalf("a machine that can prove its software was refused: %s",
			rec.Body.String())
	}
}
