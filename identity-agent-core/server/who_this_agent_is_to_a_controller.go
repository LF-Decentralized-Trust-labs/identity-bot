package server

import (
	"net/http"
	"time"
)

// What a machine asks once it has been authorised, and how it finds out.
//
// The ceremony has a gap the design has always drawn and nothing filled: the
// controller shows itself, the owner approves on the device holding the key, and
// the controller has no way to learn that it happened. There is no channel from
// the agent back to a machine it has never spoken to, and building one would
// mean a push path, a relay, and a way for a stranger to be told things.
//
// It does not need one. The controller ASKS, with the key it already holds. A
// request signed by a machine that has not been authorised is refused; the same
// request after the owner approves is served. So "am I authorised yet" is
// answered by trying, and the answer arrives without anything being pushed
// anywhere.
//
// This route is what it asks. It is the smallest useful thing an authorised
// machine can be told, and it carries the one fact the controller must record:
// WHICH IDENTITY it is now a front end for. An address is not an identity — a
// relay allocation can be reassigned, and a machine answering where the agent
// used to be is not the agent — so a controller that stored only where to go
// would trust whatever answered there next time.

// whoThisAgentIs is what an authorised machine is told about the agent.
type whoThisAgentIs struct {
	// AID is the identity this agent holds. The reason this route exists.
	AID string `json:"aid"`
	// Label is what to show the person, so the machine can say which identity
	// it is a front end for rather than showing them an identifier.
	Label string `json:"label,omitempty"`
	// YourLabel is what the owner called THIS machine when they approved it, so
	// it can show the person the same words they chose.
	YourLabel string `json:"your_label"`
	// YourGrade says whether this machine was kept or borrowed, and
	// YourAuthorisationEnds when a borrowed one stops.
	YourGrade             ControllerGrade `json:"your_grade"`
	YourAuthorisationEnds *time.Time      `json:"your_authorisation_ends,omitempty"`
}

// handleWhoThisAgentIs answers an authorised machine's "who are you, and what am
// I to you".
//
// Deliberately reachable by any live grant with nothing measured. It is the
// first thing a newly approved machine asks, at a moment when nobody has been
// authenticated for it yet — raising it would mean a controller could never
// complete the ceremony that authorises it. What it discloses is what the owner
// just agreed to on their own device, told back to the machine they agreed it
// for.
func (s *CoreServer) handleWhoThisAgentIs(w http.ResponseWriter, r *http.Request) {
	// Which machine is asking. It reached this handler, so the middleware already
	// established there is a live grant — this only reads which one.
	grant, ok := TheControllerThatAsked(r)
	if !ok {
		// The owner asking directly, which is not what this route is for and is
		// not worth a special answer.
		writeError(w, http.StatusBadRequest,
			"this route answers a machine acting for you, and this request is not from one", "")
		return
	}

	out := whoThisAgentIs{
		YourLabel: grant.Label,
		YourGrade: grant.Grade,
	}
	if !grant.ExpiresAt.IsZero() {
		ends := grant.ExpiresAt
		out.YourAuthorisationEnds = &ends
	}
	if s.DataStore != nil {
		if identity, err := s.DataStore.GetIdentity(); err == nil && identity != nil {
			out.AID = identity.AID
		}
		if profile, err := s.DataStore.GetProfile(); err == nil && profile != nil {
			out.Label = profile.FullName
			if out.Label == "" {
				out.Label = profile.Org
			}
		}
	}
	writeJSON(w, out)
}
