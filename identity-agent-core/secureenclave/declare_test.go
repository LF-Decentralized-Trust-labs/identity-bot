package secureenclave

import "testing"

// An app reports what it found; the core decides what it means. A status the
// core does not recognise must land as Unknown, never as anything it would act
// on — and above all never as Absent, which capability.go says may only ever be
// reached on positive evidence.
func TestAnAppCannotMakeTheCoreAssertSomethingItDoesNotUnderstand(t *testing.T) {
	for _, status := range []string{"", "USABLE", "yes", "secure", "hardware_backed", "absent_probably"} {
		got := normaliseDeclaredCapability(status, "android_strongbox", "r", "d")
		if got.Status != Unknown {
			t.Errorf("status %q was accepted as %q", status, got.Status)
		}
		if got.RootKeyPermitted() {
			t.Errorf("status %q would have permitted a root key", status)
		}
		if got.Kind != KindNone {
			t.Errorf("status %q kept the kind %q, which the core has no reason to believe",
				status, got.Kind)
		}
	}
}

// The four it does recognise pass through with everything the app said, because
// the detail is what anybody diagnosing a refusal actually needs.
func TestTheFourRealAnswersArriveIntact(t *testing.T) {
	for _, tc := range []struct {
		status Status
		kind   Kind
		permit bool
	}{
		{Usable, KindStrongBox, true},
		{Usable, KindAndroidTEE, true},
		{Present, KindAndroidTEE, false},
		{Absent, KindNone, false},
		{Unknown, KindNone, false},
	} {
		got := normaliseDeclaredCapability(string(tc.status), string(tc.kind), "why", "what happened")
		if got.Status != tc.status || got.Kind != tc.kind {
			t.Errorf("%s/%s came back as %s/%s", tc.status, tc.kind, got.Status, got.Kind)
		}
		if got.Detail != "what happened" {
			t.Errorf("%s lost its detail, which is what a person is shown", tc.status)
		}
		if got.RootKeyPermitted() != tc.permit {
			t.Errorf("%s permitted=%v, want %v", tc.status, got.RootKeyPermitted(), tc.permit)
		}
	}
}
