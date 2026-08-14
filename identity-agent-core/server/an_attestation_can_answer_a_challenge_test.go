package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/secureenclave"
)

// A caller can ask for a report bound to a value it chose.
//
// Without that, a report says "a sealed guest running this image produced this
// at some point" — which a report from any sibling instance also says, since
// they run the same image, and which a cached one may have said minutes ago.
// That is enough for somebody deciding whether to pair with a machine. It is
// not enough for a party that has to know THIS guest is alive and sealed now,
// which is what a host resuming an instance needs.

func TestAChallengeMustBeLongEnoughToBeUnguessable(t *testing.T) {
	s := &CoreServer{}
	if _, err := s.challengedAttestation("short"); err == nil {
		t.Fatal("a five-character challenge was accepted, so a caller could be " +
			"answered with a report somebody prepared in advance")
	}
}

func TestAChallengeIsBounded(t *testing.T) {
	s := &CoreServer{}
	if _, err := s.challengedAttestation(strings.Repeat("a", 513)); err == nil {
		t.Error("an oversized challenge was accepted")
	}
	if _, err := s.challengedAttestation("has a space in it and is long"); err == nil {
		t.Error("a challenge with a space was accepted")
	}
	if _, err := s.challengedAttestation("has\na newline in it here"); err == nil {
		t.Error("a challenge with a newline was accepted — it goes into a hash " +
			"whose input is newline-delimited")
	}
}

// Validation happens before the firmware is asked, so a bad challenge is a
// clear answer on any machine rather than a confusing one off sealed hardware.
func TestABadChallengeIsRefusedOnAnyMachine(t *testing.T) {
	s := &CoreServer{attestationLimiter: newAttestationRateLimiter(60)}
	w := httptest.NewRecorder()
	s.handlePublicAttestation(w,
		httptest.NewRequest(http.MethodGet, "/api/attestation?challenge=tiny", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a bad challenge, got %d: %s", w.Code, w.Body.String())
	}
}

// The binding a verifier recomputes. Both sides of this construction have to
// agree byte for byte or nothing verifies, so it is pinned here as well as in
// the host that checks it.
func TestAChallengeBindingIsWhatTheVerifierWillRecompute(t *testing.T) {
	const challenge = "a-host-chose-this-value-at-random"
	got := secureenclave.BindReportData(challenge)
	if len(got) != secureenclave.ReportDataSize {
		t.Fatalf("report data is %d bytes, the field is %d", len(got), secureenclave.ReportDataSize)
	}
	// Same value twice, or a verifier could never reproduce it.
	if string(got) != string(secureenclave.BindReportData(challenge)) {
		t.Fatal("the binding is not deterministic")
	}
	if string(got) == string(secureenclave.BindReportData(challenge+"x")) {
		t.Fatal("two different challenges bind to the same report data")
	}
}
