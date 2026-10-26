package sandbox

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/authprovider"
)

func atScore(score int) Person {
	return Person{AID: "ESomebody", Authenticated: authprovider.Result{
		Score: score, Measured: true, At: time.Now().UTC(), Level: authprovider.LevelForScore(score),
	}}
}

// The default minimum is 80, and the placeholder every person has today meets it.
func TestThePlaceholderScoreMeetsTheDefaultMinimum(t *testing.T) {
	who := Person{AID: "ESomebody", Authenticated: authprovider.UntilHumanAuthenticationIsBuilt(time.Now())}
	if ok, why := MayThisPersonDoThis(Action{Name: "anything"}, who); !ok {
		t.Fatalf("the placeholder score was refused an action with the default minimum: %s", why)
	}
	if ok, _ := MayThisPersonDoThis(Action{Name: "anything"}, atScore(79)); ok {
		t.Fatal("a score of 79 cleared the default minimum of 80")
	}
}

// An action whose minimum is set to 90 is refused at the placeholder 80, and
// the refusal names the score question.
func TestAnActionNeedingNinetyIsRefusedAtEighty(t *testing.T) {
	who := Person{AID: "ESomebody", Authenticated: authprovider.UntilHumanAuthenticationIsBuilt(time.Now())}
	ok, why := MayThisPersonDoThis(Action{Name: "high", MinimumScore: 90}, who)
	if ok {
		t.Fatal("an action needing 90 was allowed at 80")
	}
	if !strings.Contains(why, "90") || !strings.Contains(why, "80") {
		t.Fatalf("the refusal does not say which score was needed and which was had: %s", why)
	}
	if ok, _ := MayThisPersonDoThis(Action{Name: "high", MinimumScore: 90}, atScore(95)); !ok {
		t.Fatal("a score of 95 was refused an action needing 90")
	}
}

// Nothing measured is not a score of zero that might clear a low minimum.
func TestNothingMeasuredClearsNothing(t *testing.T) {
	who := Person{AID: "ESomebody", Authenticated: authprovider.Unmeasured("nothing")}
	if ok, _ := MayThisPersonDoThis(Action{Name: "low", MinimumScore: 1}, who); ok {
		t.Fatal("an unmeasured person cleared a minimum of 1")
	}
}

// A minimum that is not a score refuses everybody rather than letting
// everybody through.
func TestANegativeMinimumRefusesEverybody(t *testing.T) {
	if ok, _ := MayThisPersonDoThis(Action{Name: "typo", MinimumScore: -5}, atScore(100)); ok {
		t.Fatal("a negative minimum let a caller through")
	}
}

// A capability's minimum is honoured where the gateway authorises an
// invocation: one set to 90 is refused at the placeholder 80, and the refusal
// is audited. Before the one check existed the gateway had no identity
// requirement at all, and this call ran.
func TestACapabilityNeedingNinetyIsRefusedAtTheGateway(t *testing.T) {
	ran := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	m := registryTestManager(t)
	rec := CapabilityRecord{
		ID: "testsvc.high", Name: "High", ExecutorType: "external_api", Impact: "mutating",
		Egress:   &EgressSpec{BaseURL: ts.URL, Method: "POST", PathTemplate: "/x"},
		Provider: "registry-native", Enabled: true,
		MinimumScore: 90,
	}
	if err := m.store.UpsertCapabilityRecord(rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if got, _ := m.store.GetCapabilityRecord("testsvc.high"); got == nil || got.MinimumScore != 90 {
		t.Fatalf("the minimum did not survive being stored: %+v", got)
	}

	caller := CallerContext{CallerAID: "local-owner", CorrelationID: "corr-90"}
	_, err := m.InvokeCapability(context.Background(), caller, "testsvc.high", []byte(`{}`))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("a capability needing 90 was not refused at 80: %v", err)
	}
	if ran {
		t.Fatal("the capability ran")
	}
	events, _ := m.store.QueryInvocationEvents(InvocationEventFilter{CapabilityID: "testsvc.high"})
	if len(events) != 1 || events[0].ResultStatus != "denied" {
		t.Fatalf("the refusal was not audited: %+v", events)
	}
}

// A record that sets no minimum keeps the content address it had before the
// field existed, so no capability's SAID moved. The value is pinned from the
// code before minimum_score was added.
func TestNoMinimumLeavesTheContentAddressAlone(t *testing.T) {
	const before = "blake3:06b432e629b78f257a3313631db57da091ef71f82c7a9f9fd1eb320fe843c6e0"
	rec := CapabilityRecord{ID: "demo.pinned", Name: "Pinned", Domain: "demo",
		ExecutorType: "external_api", Impact: "read", Provider: "registry-native", Enabled: true}
	if got := computeCapabilitySAID(rec); got != before {
		t.Fatalf("a record with no minimum changed its content address: %s, was %s", got, before)
	}
	rec.MinimumScore = 90
	if computeCapabilitySAID(rec) == before {
		t.Fatal("a set minimum is not part of what the content address covers")
	}
}
