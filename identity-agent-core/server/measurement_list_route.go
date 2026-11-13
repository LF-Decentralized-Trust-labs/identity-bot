package server

import (
	"errors"
	"io"
	"net/http"
	"time"

	"identity-agent-core/measurementlist/anchored"
)

// handleMeasurementList takes a candidate bundle of the publisher's list (what
// an app has fetched: the publisher's key history, its registry's events and the
// list credentials), asks the publisher's witnesses for the publisher's latest
// state, and checks the bundle against that, the pin this build holds and the
// floors this core keeps. Only a list that holds becomes the policy, and the
// floors then rise. The bundle carries no trust of its own: the app that
// delivered it decides nothing, and may deliver it as often as it likes.
//
// The answer says in words what is wrong, so an app can show it: the bundle is
// behind the witnesses (fetch a newer one), the witnesses could not be asked
// (try again), the publisher's history conflicts with the one held here (the
// evidence is kept), or the list is not one this build accepts.
func (s *CoreServer) handleMeasurementList(w http.ResponseWriter, r *http.Request) {
	if s.measurementLists == nil {
		writeError(w, http.StatusServiceUnavailable, "This core keeps no list of software", "it was not set up to")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, anchored.MaxBundleBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "The bundle cannot be read", err.Error())
		return
	}
	res, err := s.measurementLists.check(r.Context(), raw)
	if err != nil {
		status, title := http.StatusUnprocessableEntity, "This list of software is not accepted"
		var dup *anchored.Duplicity
		switch {
		case errors.Is(err, anchored.ErrNoPin):
			status, title = http.StatusConflict, "This build trusts no publisher of software lists"
		case errors.Is(err, anchored.ErrNotFresh):
			status, title = http.StatusServiceUnavailable, "The publisher's witnesses could not be asked just now"
		case errors.Is(err, anchored.ErrBehind):
			status, title = http.StatusConflict, "The bundle is older than what the publisher's witnesses hold"
		case errors.As(err, &dup):
			status, title = http.StatusConflict, "The publisher's history conflicts with the one this core holds"
		}
		writeError(w, status, title, err.Error())
		return
	}
	kinds := map[string]int{}
	for kind := range res.List.Images {
		kinds[kind] = len(res.List.MeasurementsAt(kind, res.List.At))
	}
	writeJSON(w, map[string]any{
		"sequence": res.List.Sequence, "credential": res.CredentialSAID,
		"expires_at":    res.List.ExpiresAt.UTC().Format(time.RFC3339),
		"history_place": res.Tip.SN, "accepted_by_kind": kinds,
	})
}
