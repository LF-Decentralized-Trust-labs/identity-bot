package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The endpoint is open, which is a decision rather than an oversight, so the
// behaviour that makes it safe to be open is worth pinning.

// Open by necessity: a client verifies a machine in order to decide whether to
// trust it, so it cannot be required to already be the owner.
func TestTheAttestationEndpointIsReachableWithoutBeingTheOwner(t *testing.T) {
	if classify(http.MethodGet, "/api/attestation") != accessPublic {
		t.Fatal("the attestation endpoint is not public, so a client that has not " +
			"yet adopted an agent cannot verify it — which is the circularity this " +
			"endpoint exists to break")
	}
}

// The whole enclave status carries key backing, genuineness and trust-gate
// state. Those are the owner's business and are not needed to decide whether a
// machine is sealed, so opening the narrow endpoint must not have opened that.
func TestOpeningAttestationDidNotOpenTheOwnerStatus(t *testing.T) {
	if classify(http.MethodGet, "/api/security/enclave") == accessPublic {
		t.Fatal("the full enclave status became public; it carries more than the " +
			"evidence a stranger needs")
	}
}

func TestOneCallerCannotDriveUnboundedFirmwareWork(t *testing.T) {
	l := newAttestationRateLimiter(3)
	for i := 0; i < 3; i++ {
		if !l.allow("10.0.0.1") {
			t.Fatalf("refused request %d, which is within the limit", i+1)
		}
	}
	if l.allow("10.0.0.1") {
		t.Fatal("a caller past the limit was allowed through")
	}
	// One noisy caller must not lock out everybody else.
	if !l.allow("10.0.0.2") {
		t.Fatal("a different caller was refused because of another's traffic")
	}
}

// The limiter's map is keyed by something an unauthenticated caller chooses, so
// it has to forget. Otherwise it is a slow leak they control the size of.
func TestTheLimiterForgetsOldCallers(t *testing.T) {
	l := newAttestationRateLimiter(1)
	l.allow("10.0.0.1")
	// Age the entry past its window and force a sweep.
	l.mu.Lock()
	l.seen["10.0.0.1"].start = time.Now().Add(-2 * time.Minute)
	l.lastGC = time.Now().Add(-2 * time.Minute)
	l.mu.Unlock()

	if !l.allow("10.0.0.2") {
		t.Fatal("a fresh caller was refused")
	}
	l.mu.Lock()
	_, stillThere := l.seen["10.0.0.1"]
	l.mu.Unlock()
	if stillThere {
		t.Fatal("an expired caller was kept, so the map grows without bound")
	}
}

// A nil limiter must not refuse everything. Any path that builds a server
// without one should degrade to unlimited rather than to unusable.
func TestANilLimiterAllows(t *testing.T) {
	var l *attestationRateLimiter
	if !l.allow("10.0.0.1") {
		t.Fatal("a server with no limiter refused every request")
	}
}

// On a machine with no sealed hardware the honest answer is "there is nothing
// to prove", not an error suggesting something is broken.
func TestAnOrdinaryMachineSaysSoRatherThanFailing(t *testing.T) {
	s := &CoreServer{attestationLimiter: newAttestationRateLimiter(60)}
	rec := httptest.NewRecorder()
	s.handlePublicAttestation(rec, httptest.NewRequest(http.MethodGet, "/api/attestation", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 for a machine with no sealed hardware", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "not_sealed_hardware") {
		t.Fatalf("the answer does not say why: %s", body)
	}
}

// The response says HOW the report was bound, never WHAT it was bound to.
//
// This field once carried the construction with the value inside it, on an
// endpoint open to anyone — which handed over precisely what the one-way
// function was there to protect, and did it beside a comment asserting that
// nothing identifying was disclosed. Where the binding was an identity rather
// than a transport key, that published the tenant's identifier to any caller.
//
// A verifier does not need the value: it holds what the binding is over and
// recomputes. Only somebody who does NOT hold it gains anything from being
// told.
func TestTheBindingSchemeIsPublishedButNeverTheValue(t *testing.T) {
	for _, binding := range []string{
		"EPlFRfTkHsTDBcvSkIrd90_fUFi3lYHXw-3uZulr19VN", // an identity
		"3q2+7w==", // a transport fingerprint
	} {
		got := bindingScheme(binding, "")
		if got == "" {
			t.Fatalf("no scheme was published for %q, so nothing could recompute the binding", binding)
		}
		if strings.Contains(got, binding) {
			t.Errorf("the value %q appears in what is published: %s", binding, got)
		}
	}
	// And it still says enough to be recomputed.
	scheme := bindingScheme("anything", "")
	for _, needed := range []string{"blake3-256", "IA-SNP-BIND-V1"} {
		if !strings.Contains(scheme, needed) {
			t.Errorf("the scheme omits %q, so a verifier could not reproduce the binding", needed)
		}
	}
}

// Nothing identifying in the whole response. The check above covers the field
// that was wrong; this covers the response, because the next such field would
// be added somewhere else.
func TestNoIdentifierAppearsAnywhereInThePublicAttestation(t *testing.T) {
	const identity = "EPlFRfTkHsTDBcvSkIrd90_fUFi3lYHXw-3uZulr19VN"
	out := &publicAttestation{
		Platform:    "sev-snp",
		Measurement: "aa",
		ChipID:      "bb",
		BoundTo:     bindingScheme(identity, ""),
		Note:        "checked",
	}
	body, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), identity) {
		t.Fatalf("an identifier reached an endpoint open to anyone:\n%s", body)
	}
}
