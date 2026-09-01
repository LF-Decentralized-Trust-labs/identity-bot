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

// EVERY WAY IN IS REFUSED, not just the one named "inception".
//
// A gate on one route out of several is worse than no gate, because it reads as
// closed. This one covered founding directly and missed four others: a computer
// founding its own root as it is paired, a break-glass path called a rotation
// that mints a new root at sequence zero, a hybrid inception that produces real
// key material, and the route that stores an identity somebody else made — the
// last two of which compose into a founding out of parts.
//
// They do not resemble each other, which is the point. Anything added later
// that brings an identity into being on this machine belongs in this list on
// sight, and if it is not here somebody has to notice, which is what this test
// is for.
func TestEveryWayAnIdentityCanBeginIsRefusedOnAMachineThatMayNotFound(t *testing.T) {
	refuseHere := func(t *testing.T) {
		t.Helper()
		was := mayFoundAnIdentityHere
		mayFoundAnIdentityHere = func() foundingVerdict {
			return foundingVerdict{
				Permitted: false, Platform: "macos",
				Why: cannotProveItsSoftware, Instead: actForOneInstead,
			}
		}
		t.Cleanup(func() { mayFoundAnIdentityHere = was })
	}

	for _, door := range []struct {
		what   string
		method string
		path   string
		body   string
		call   func(*CoreServer, http.ResponseWriter, *http.Request)
	}{
		{
			what: "founding directly", method: http.MethodPost, path: "/api/inception",
			body: `{"public_key":"D1","next_public_key":"D2"}`,
			call: (*CoreServer).handleInception,
		},
		{
			// Named a rotation, and it mints a NEW root at sequence zero. The
			// name is exactly why it was missed.
			what:   "a rotation that is really a founding",
			method: http.MethodPost, path: "/api/recovery/root-aid-rotation",
			body: `{}`,
			call: (*CoreServer).handleRecoveryRootAIDRotation,
		},
		{
			what: "hybrid inception", method: http.MethodPost, path: "/api/hybrid-inception",
			body: `{}`,
			call: (*CoreServer).handleHybridInception,
		},
		{
			what:   "storing an identity somebody else made",
			method: http.MethodPost, path: "/api/store/identity",
			body: `{"aid":"EWHATEVER","public_key":"D1"}`,
			call: (*CoreServer).handleStoreIdentity,
		},
		{
			// The more consequential half of that pair: it writes the event into
			// this machine's key log AND publishes it to the witnesses.
			what:   "storing an inception event",
			method: http.MethodPost, path: "/api/store/event",
			body: `{"aid":"EWHATEVER","event_type":"icp","sequence_number":0}`,
			call: (*CoreServer).handleStoreEvent,
		},
	} {
		t.Run(door.what, func(t *testing.T) {
			s := agentWithNoIdentity(t)
			refuseHere(t)

			req := httptest.NewRequest(door.method, door.path, strings.NewReader(door.body))
			req.RemoteAddr = "127.0.0.1:1234"
			rec := httptest.NewRecorder()
			door.call(s, rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s is not refused on a computer that cannot prove its "+
					"software: %d %s", door.what, rec.Code, rec.Body.String())
			}
		})
	}
}

// A computer founding its own root as it is paired is refused too.
//
// Its own test because it needs a pairing already begun: without one the
// handler refuses for having nothing to complete, which is a different refusal
// and would let this pass with the check deleted. The ceremony matters — it is
// the one that replaced the withdrawn design, and it was the way round the gate
// on the direct route.
func TestAComputerThatMayNotFoundIsRefusedWhileBeingPaired(t *testing.T) {
	machine, srv, code := pairableComputer(t)

	// The key material exists by this point, which is the honest limit of what
	// this refuses: the offer and the begin already happened. What it stops is
	// an identity; the material is discarded unused.
	_ = beginAt(t, srv.URL)

	was := mayFoundAnIdentityHere
	mayFoundAnIdentityHere = func() foundingVerdict {
		return foundingVerdict{
			Permitted: false, Platform: "macos",
			Why: cannotProveItsSoftware, Instead: actForOneInstead,
		}
	}
	t.Cleanup(func() { mayFoundAnIdentityHere = was })

	body := `{"found_as_root":true,"owner_aid":"EOWNER","adoption_code":"` + code + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/complete",
		strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	machine.handlePairingComplete(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("a computer that cannot prove its software founded its own root "+
			"while being paired: %d %s", rec.Code, rec.Body.String())
	}
}

// An identity that already exists goes on living on a machine that may not have
// founded it.
//
// The gate is about where an identity BEGINS. Refusing a rotation, an
// interaction or a receipt would stop one continuing, which is a different and
// much worse thing: four identities already exist on machines that may not have
// founded them, and cutting them off is not a security improvement, it is
// somebody losing their identity.
func TestAnIdentityThatAlreadyExistsGoesOnWorking(t *testing.T) {
	for _, kind := range []string{"rot", "ixn", "rct"} {
		t.Run(kind, func(t *testing.T) {
			s := agentWithNoIdentity(t)
			was := mayFoundAnIdentityHere
			mayFoundAnIdentityHere = func() foundingVerdict {
				return foundingVerdict{
					Permitted: false, Platform: "macos",
					Why: cannotProveItsSoftware, Instead: actForOneInstead,
				}
			}
			t.Cleanup(func() { mayFoundAnIdentityHere = was })

			body := `{"aid":"EWHATEVER","event_type":"` + kind + `","sequence_number":1}`
			req := httptest.NewRequest(http.MethodPost, "/api/store/event",
				strings.NewReader(body))
			req.RemoteAddr = "127.0.0.1:1234"
			rec := httptest.NewRecorder()
			s.handleStoreEvent(rec, req)

			if rec.Code == http.StatusForbidden {
				t.Fatalf("a %s event was refused, so an identity that already "+
					"exists here cannot go on working: %s", kind, rec.Body.String())
			}
		})
	}
}
