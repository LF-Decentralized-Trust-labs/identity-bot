package server

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/witness"
)

// A registry log stands for "not revoked" only when as many of the issuer's
// witnesses as its key log requires (its toad) agree on it and on how far the
// key log goes. Witnesses that do not answer are not votes: with too few
// answering the credential is "could not check", never "not revoked" (SEAM-13
// T-4).

// threeWitnesses is an issuer witnessed by three with a threshold of two. Only
// the first holds anything; the pool is given by the caller, whose entries for
// the other two are whatever each test makes them.
func threeWitnesses(t *testing.T) (*registryWorld, *drivers.DriverIssueCredentialResponse, [3]string) {
	t.Helper()
	a, b, c := startPeer(t, "a"), startPeer(t, "b"), startPeer(t, "c")
	ctl := newRotatingControllerWitnessedByToad(t, "subject", 2, a.witnessKey, b.witnessKey, c.witnessKey)
	a.willWitnessFor(t, ctl.aid)
	if err := a.takes(t, ctl.aid, ctl.icpRaw, ctl.icpSig); err != nil {
		t.Fatalf("a witness would not take the inception: %v", err)
	}
	w := registryWorldOf(t, a, ctl)
	reg := w.inceptRegistry(true)
	iss := w.issue(reg.RegistrySaid, true)
	w.post(vcpB64(reg), iss.IssRawBytesB64)
	return w, iss, [3]string{a.witnessKey, b.witnessKey, c.witnessKey}
}

func withThePool(t *testing.T, pool ...witness.BootstrapWitness) {
	t.Helper()
	prior := witness.BootstrapWitnesses
	witness.BootstrapWitnesses = func() []witness.BootstrapWitness { return pool }
	t.Cleanup(func() { witness.BootstrapWitnesses = prior })
}

// anotherWayTo is a second address that serves exactly what the witness at base does.
func anotherWayTo(t *testing.T, base string) string {
	t.Helper()
	target, _ := url.Parse(base)
	srv := httptest.NewServer(httputil.NewSingleHostReverseProxy(target))
	t.Cleanup(srv.Close)
	return srv.URL
}

func unreachable(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	return url
}

func TestOneWitnessAnsweringOfThreeWithAThresholdOfTwoIsCouldNotCheck(t *testing.T) {
	w, iss, k := threeWitnesses(t)
	withThePool(t,
		witness.BootstrapWitness{AID: "EA", WitnessKey: k[0], URL: w.base, Operator: "tests"},
		witness.BootstrapWitness{AID: "EB", WitnessKey: k[1], URL: unreachable(t), Operator: "tests"},
		witness.BootstrapWitness{AID: "EC", WitnessKey: k[2], URL: unreachable(t), Operator: "tests"})
	notVouchedFor(t, w.verifyWithThePool(iss), "one witness of three, threshold two")
}

func TestTwoWitnessesAgreeingWithAThresholdOfTwoIsNotRevoked(t *testing.T) {
	w, iss, k := threeWitnesses(t)
	withThePool(t,
		witness.BootstrapWitness{AID: "EA", WitnessKey: k[0], URL: w.base, Operator: "tests"},
		witness.BootstrapWitness{AID: "EB", WitnessKey: k[1], URL: anotherWayTo(t, w.base), Operator: "tests"},
		witness.BootstrapWitness{AID: "EC", WitnessKey: k[2], URL: unreachable(t), Operator: "tests"})
	res := w.verifyWithThePool(iss)
	if !res.Verified || res.Checks["not_revoked"] != true {
		t.Fatalf("two witnesses agreeing did not make the log complete: verified=%v checks=%+v errors=%v", res.Verified, res.Checks, res.Errors)
	}
}

func TestTwoWitnessesDisagreeingIsAConflictNotAVerdict(t *testing.T) {
	w, iss, k := threeWitnesses(t)
	_, honest := w.get("/api/witness/tel/"+w.c.aid+"?since_sn=-1", true)
	silent := honest
	silent.Events = nil // the same key-log position, with the credential's events left out
	other := front(t, w.base, func(rw http.ResponseWriter, _ *http.Request) { serveAnswer(rw, silent) })
	withThePool(t,
		witness.BootstrapWitness{AID: "EA", WitnessKey: k[0], URL: w.base, Operator: "tests"},
		witness.BootstrapWitness{AID: "EB", WitnessKey: k[1], URL: other, Operator: "tests"},
		witness.BootstrapWitness{AID: "EC", WitnessKey: k[2], URL: unreachable(t), Operator: "tests"})
	res := w.verifyWithThePool(iss)
	notVouchedFor(t, res, "two witnesses that disagree")
	if res.Checks["possible_duplicity"] != true {
		t.Fatalf("a conflict between witnesses was not reported: checks=%+v errors=%v", res.Checks, res.Errors)
	}
}
