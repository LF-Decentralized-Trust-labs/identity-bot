package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	l := newIPRateLimiter(3, time.Minute)
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
	at := time.Now()
	l := newIPRateLimiterAt(1, time.Minute, func() time.Time { return at })
	l.allow("10.0.0.1")
	// Fill the table, then age every entry past its window so a sweep is forced.
	for i := 0; i < maxRateLimitedClients-1; i++ {
		l.allow("filler-" + strconv.Itoa(i))
	}
	at = at.Add(2 * time.Minute)

	if !l.allow("10.0.0.2") {
		t.Fatal("a fresh caller was refused")
	}
	stillThere := l.w.Remembers("10.0.0.1")
	if stillThere {
		t.Fatal("an expired caller was kept, so the map grows without bound")
	}
}

// The attestation route names its caller the same way every other public route
// does: a forwarding header counts only from a configured trusted proxy.
func TestAttestationRouteHonoursTrustedProxiesAndStaysLimited(t *testing.T) {
	call := func(s *CoreServer, remote, xff string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/attestation", nil)
		req.RemoteAddr = remote
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		rec := httptest.NewRecorder()
		s.handlePublicAttestation(rec, req)
		return rec.Code
	}

	// No trusted proxy: a forged header buys no new identity.
	t.Setenv("TRUSTED_PROXIES", "")
	s := &CoreServer{attestationLimiter: newIPRateLimiter(2, time.Minute)}
	for i := 0; i < 2; i++ {
		call(s, "203.0.113.9:1000", "198.51.100."+strconv.Itoa(i+1))
	}
	if got := call(s, "203.0.113.9:1000", "198.51.100.99"); got != http.StatusTooManyRequests {
		t.Fatalf("a forged X-Forwarded-For escaped the limit: status %d", got)
	}

	// Behind a trusted proxy: visitors are told apart by the forwarded address.
	t.Setenv("TRUSTED_PROXIES", "10.0.0.1")
	s = &CoreServer{attestationLimiter: newIPRateLimiter(1, time.Minute)}
	if got := call(s, "10.0.0.1:1000", "198.51.100.1"); got == http.StatusTooManyRequests {
		t.Fatalf("first visitor refused: %d", got)
	}
	if got := call(s, "10.0.0.1:1000", "198.51.100.2"); got == http.StatusTooManyRequests {
		t.Fatal("a second visitor behind the proxy shared the first one's quota")
	}
	if got := call(s, "10.0.0.1:1000", "198.51.100.1"); got != http.StatusTooManyRequests {
		t.Fatalf("the same visitor was not limited: status %d", got)
	}
}

// A nil limiter must not refuse everything. Any path that builds a server
// without one should degrade to unlimited rather than to unusable.
func TestANilLimiterAllows(t *testing.T) {
	var l *ipRateLimiter
	if !l.allow("10.0.0.1") {
		t.Fatal("a server with no limiter refused every request")
	}
}

// On a machine with no sealed hardware the honest answer is "there is nothing
// to prove", not an error suggesting something is broken.
func TestAnOrdinaryMachineSaysSoRatherThanFailing(t *testing.T) {
	s := &CoreServer{attestationLimiter: newIPRateLimiter(60, time.Minute)}
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
