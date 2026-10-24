package appcall

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var anAIAgent = Caller{
	Kind: KindAIAgent, Agent: "EAgent", Machine: "BBody", AuthLevel: "body_signed",
	Grant: "EGrant", Session: "run-7",
}

func keyAndVerifier(t *testing.T) ([]byte, *Verifier) {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, v
}

func stamped(t *testing.T, k []byte, capability string, body []byte, c Caller) http.Header {
	t.Helper()
	h := http.Header{}
	if err := Stamp(h, k, capability, body, c, time.Now()); err != nil {
		t.Fatal(err)
	}
	return h
}

// The app learns exactly who the Identity Agent admitted.
func TestAStampedCallNamesItsCaller(t *testing.T) {
	k, v := keyAndVerifier(t)
	body := []byte(`{"task":"T-1"}`)
	got, err := v.Verify(stamped(t, k, "tracker.lease", body, anAIAgent), "tracker.lease", body)
	if err != nil {
		t.Fatalf("a call the Identity Agent stamped was refused: %v", err)
	}
	if got != anAIAgent {
		t.Fatalf("the app was told %+v, not %+v", got, anAIAgent)
	}
}

// Every field is covered: changing any of them, the body, or the capability
// makes the call worthless.
func TestNothingInAStampedCallCanBeChanged(t *testing.T) {
	k, v := keyAndVerifier(t)
	body := []byte(`{"task":"T-1"}`)
	for _, name := range []string{HeaderKind, HeaderAgent, HeaderMachine, HeaderAuthLevel,
		HeaderGrant, HeaderSession, HeaderNonce} {
		h := stamped(t, k, "tracker.lease", body, anAIAgent)
		h.Set(name, "changed")
		if _, err := v.Verify(h, "tracker.lease", body); err == nil {
			t.Errorf("a call with %s changed was accepted", name)
		}
	}
	if _, err := v.Verify(stamped(t, k, "tracker.lease", body, anAIAgent), "tracker.lease",
		[]byte(`{"task":"T-2"}`)); err == nil {
		t.Error("a call with its body changed was accepted")
	}
	if _, err := v.Verify(stamped(t, k, "tracker.read", body, anAIAgent), "tracker.lease", body); err == nil {
		t.Error("a call stamped for one capability was accepted for another")
	}
}

// Headers a caller set itself, with no MAC or a MAC under another key, are
// refused: only the Identity Agent can say who called.
func TestACallerCannotNameItself(t *testing.T) {
	_, v := keyAndVerifier(t)
	body := []byte(`{}`)
	h := http.Header{}
	h.Set(HeaderCapability, "tracker.lease")
	h.Set(HeaderKind, KindOwner)
	h.Set(HeaderTime, time.Now().UTC().Format(time.RFC3339))
	h.Set(HeaderNonce, "aaaaaaaaaaaaaaaaaaaaaaaa")
	if _, err := v.Verify(h, "tracker.lease", body); err == nil {
		t.Fatal("a call with no MAC was accepted")
	}
	other, _ := NewKey()
	if _, err := v.Verify(stamped(t, other, "tracker.lease", body, Caller{Kind: KindOwner}), "tracker.lease", body); err == nil {
		t.Fatal("a call stamped under another app's key was accepted")
	}
}

// A call is received once, and only inside the window.
func TestACallIsReceivedOnceAndOnlyWhileFresh(t *testing.T) {
	k, v := keyAndVerifier(t)
	body := []byte(`{}`)
	h := stamped(t, k, "tracker.lease", body, anAIAgent)
	if _, err := v.Verify(h, "tracker.lease", body); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(h, "tracker.lease", body); err == nil {
		t.Fatal("the same call was received twice")
	}
	old := http.Header{}
	if err := Stamp(old, k, "tracker.lease", body, anAIAgent, time.Now().Add(-3*Window)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(old, "tracker.lease", body); err == nil {
		t.Fatal("a stale call was accepted")
	}
}

// Stamping replaces whatever call headers a request already carried.
func TestStampingReplacesWhatACallerSent(t *testing.T) {
	k, v := keyAndVerifier(t)
	h := http.Header{}
	h.Set(HeaderKind, KindOwner)
	h.Set("X-Ia-Call-Something-New", "planted")
	if err := Stamp(h, k, "tracker.lease", nil, anAIAgent, time.Now()); err != nil {
		t.Fatal(err)
	}
	if h.Get("X-Ia-Call-Something-New") != "" {
		t.Fatal("a planted call header survived stamping")
	}
	got, err := v.Verify(h, "tracker.lease", nil)
	if err != nil || got.Kind != KindAIAgent {
		t.Fatalf("the stamp did not replace the planted kind: %+v %v", got, err)
	}
}

// Require serves only stamped calls, and hands the handler the caller.
func TestRequireServesOnlyStampedCalls(t *testing.T) {
	k, v := keyAndVerifier(t)
	var seen Caller
	srv := httptest.NewServer(v.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = FromContext(r.Context())
	})))
	defer srv.Close()

	body := []byte(`{"a":1}`)
	req, _ := http.NewRequest("POST", srv.URL+"/v1/capability/tracker.lease", bytes.NewReader(body))
	if err := Stamp(req.Header, k, "tracker.lease", body, anAIAgent, time.Now()); err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK || seen != anAIAgent {
		t.Fatalf("a stamped call was not served with its caller: %d %+v", res.StatusCode, seen)
	}

	seen = Caller{}
	res, err = http.Post(srv.URL+"/v1/capability/tracker.lease", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized || seen != (Caller{}) {
		t.Fatalf("an unstamped call reached the handler: %d %+v", res.StatusCode, seen)
	}
}

// An app the Identity Agent started without a key refuses to start checking,
// rather than accepting calls unchecked.
func TestAnAppWithNoKeyHasNoVerifier(t *testing.T) {
	t.Setenv(KeyEnv, "")
	if _, err := VerifierFromEnv(); err == nil {
		t.Fatal("an app with no key got a verifier")
	}
	k, _ := NewKey()
	t.Setenv(KeyEnv, EncodeKey(k))
	if _, err := VerifierFromEnv(); err != nil {
		t.Fatalf("an app with its key got no verifier: %v", err)
	}
}

// A line break cannot be used to move one field into another.
func TestAFieldCannotCarryALineBreak(t *testing.T) {
	k, _ := NewKey()
	if err := Stamp(http.Header{}, k, "tracker.lease", nil, Caller{Kind: KindAIAgent, Agent: "E\nowner"}, time.Now()); err == nil {
		t.Fatal("a field with a line break was stamped")
	}
}
