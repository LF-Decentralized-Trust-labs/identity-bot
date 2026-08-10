package server

import (
	"encoding/json"
	"net/http"

	keri "github.com/grapeid/keri-go"
)

// handleKeriSelfTest runs the KERI conformance suite in this process and
// reports the result.
//
// It exists because the platforms this agent runs on cannot all run a Go test
// binary. A phone in particular cannot, so until now the only evidence the KERI
// implementation was correct there was that it was correct on a developer's
// laptop. The architecture matches; the runtime does not — a different libc
// surface through cgo, a sandboxed filesystem, tighter memory — and an
// implementation can be byte-perfect on one and wrong on the other.
//
// The vectors are embedded in the library, so this reads no files and is safe
// to call at any time. It is a diagnostic: it changes no state and touches no
// keys.
//
// The response reports what was NOT checked as well as what passed. A number of
// the cases produce no bytes to compare — code tables, state transitions,
// refusals — and are verified by assertions in the library's own test suite
// instead. Counting those as passes would let a run claim more coverage than it
// has, so they are reported separately.
func (s *CoreServer) handleKeriSelfTest(w http.ResponseWriter, r *http.Request) {
	result := keri.SelfTest()

	w.Header().Set("Content-Type", "application/json")
	// A failing suite is reported as a server error, so a caller that only
	// checks the status code cannot read a broken implementation as healthy.
	if !result.OK() {
		w.WriteHeader(http.StatusInternalServerError)
	}
	if err := json.NewEncoder(w).Encode(map[string]any{
		"ok":                 result.OK(),
		"total":              result.Total,
		"passed":             result.Passed,
		"failed":             result.Failed,
		"asserted_elsewhere": result.AssertedElsewhere,
		"unimplemented":      result.Unimplemented,
		"cases":              result.Cases,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
