//go:build !kerigo_pqtest

package server

import (
	"net/http"
	"strings"
	"testing"
)

// CESR has assigned no post-quantum code, so a default build reads none: it
// refuses to prepare a rotation that reveals a post-quantum key, and the
// keymath operation that writes the signature code is not there.
func TestADefaultBuildRefusesAStageTwoRotation(t *testing.T) {
	s, aid, k, _, pqKeys := aStageOneIdentity(t)
	code, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", aStageTwoRotationRequest(t, aid, k, pqKeys))
	if code == http.StatusOK {
		t.Fatalf("a default build prepared a stage-two rotation: %v", out)
	}
	if d, _ := out["details"].(string); !strings.Contains(d, "under no code this build reads") {
		t.Fatalf("refused for another reason than the missing code: %v", out)
	}
	if own, _ := s.DataStore.GetIdentity(); own == nil || own.EventCount != 1 {
		t.Fatalf("the refusal changed the log: %+v", own)
	}
}
