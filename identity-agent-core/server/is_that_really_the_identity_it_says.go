package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Checking that the identity answering at an address is the one it claims.
//
// A COMPUTER ASKING TO ACT FOR AN IDENTITY HAS TO CHECK THE OTHER WAY TOO.
// Everything else in this area is about the agent satisfying itself that a
// request came from a machine it authorised. This is the reverse, and it was
// missing entirely: the machine took the identifier the agent reported at face
// value and wrote it down as the identity it now fronts for. Anything at that
// address could name any identity and be believed — and once it is written
// down, every later launch trusts it.
//
// WHAT MAKES THE ANSWER WORTH ANYTHING is that a key event log is
// self-verifying. The identifier is derived from the inception event, so a log
// that checks out cannot name an identifier other than the one it belongs to.
// Nobody has to be trusted for this: not the agent, not the address, not
// whatever is in between.
//
// It runs on the ASKING computer's own core, because that is the only party
// with an engine it controls. Asking the agent to verify itself would be asking
// the thing under question to answer for itself.

type verifyIdentityRequest struct {
	// AID is what the far side claims to be.
	AID string `json:"aid"`
	// OobiURL is where its key history is published.
	OobiURL string `json:"oobi_url"`
}

type verifyIdentityResponse struct {
	// Verified is the whole answer. False for every reason — unreachable, no
	// history published, a history that did not check out, one that names a
	// different identity — because a caller acting on this has the same choice
	// in all of them, and telling them apart invites treating some as good
	// enough.
	Verified bool `json:"verified"`
	// AID as established by the log, which the caller compares against what it
	// was told. Empty when nothing was established.
	AID string `json:"aid,omitempty"`
	// PublicKey the log puts in force, for a caller that wants to check a
	// signature against it later.
	PublicKey string `json:"public_key,omitempty"`
	// Why, in words for a person, when it is not verified.
	Why string `json:"why,omitempty"`
}

func (s *CoreServer) handleVerifyAnIdentityElsewhere(w http.ResponseWriter, r *http.Request) {
	var req verifyIdentityRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be JSON", err.Error())
		return
	}
	aid := strings.TrimSpace(req.AID)
	oobi := strings.TrimSpace(req.OobiURL)
	if aid == "" || oobi == "" {
		writeError(w, http.StatusBadRequest,
			"say which identity, and where its key history is published", "")
		return
	}

	if s.KeriDriver == nil {
		// Said rather than assumed. A machine with no engine cannot check this,
		// and answering "not verified" would be indistinguishable from a failed
		// check — which is the difference between "do not trust that" and "this
		// computer cannot tell".
		writeError(w, http.StatusNotImplemented,
			"this computer has no key engine, so it cannot check who is at that address",
			"an identity that cannot be checked must not be acted on")
		return
	}

	events, err := fetchKELFromOOBI(oobi)
	if err != nil {
		writeJSON(w, verifyIdentityResponse{
			Why: fmt.Sprintf("could not read the key history at %s: %v", oobi, err)})
		return
	}
	if len(events) == 0 {
		writeJSON(w, verifyIdentityResponse{
			Why: "that address published no key history, so nothing there can be checked"})
		return
	}

	val, verr := s.KeriDriver.ValidateKEL(aid, events)
	if verr != nil {
		writeJSON(w, verifyIdentityResponse{
			Why: fmt.Sprintf("the check could not run: %v", verr)})
		return
	}
	if !val.KelVerified {
		why := "that key history did not check out"
		if len(val.ValidationErrors) > 0 {
			why = val.ValidationErrors[0]
		}
		writeJSON(w, verifyIdentityResponse{Why: why})
		return
	}
	// VERIFIED WITH NO KEY IS NOT VERIFIED, the same rule as the contact check
	// next door and for the same reason: an answer of yes with nothing to check
	// signatures against is one nobody can act on, and it would be acted on
	// anyway.
	if val.CurrentPublicKey == "" {
		writeJSON(w, verifyIdentityResponse{
			Why: "that key history checked out and named no current key, which is " +
				"not something this computer can act on"})
		return
	}

	writeJSON(w, verifyIdentityResponse{
		Verified:  true,
		AID:       aid,
		PublicKey: val.CurrentPublicKey,
	})
}
