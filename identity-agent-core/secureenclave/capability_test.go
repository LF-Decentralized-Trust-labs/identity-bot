package secureenclave

import (
	"strings"
	"testing"
)

// The whole contract in one test: only proven hardware may hold a root key.
//
// The permissive mistake here is the one that cannot be undone. A machine we
// merely failed to check, treated as capable, puts somebody's identity in a
// plain file — and unlike almost every other error, nobody finds out until the
// file has already been copied.
func TestOnlyProvenHardwareMayHoldARootKey(t *testing.T) {
	cases := []struct {
		name   string
		cap    Capability
		permit bool
	}{
		{"proven usable", Capability{Status: Usable, Kind: KindTPM2}, true},
		{"present but locked out", Capability{Status: Present, Kind: KindTPM2, Reason: "locked_out"}, false},
		{"proven absent", Capability{Status: Absent, Reason: "no_tpm"}, false},
		{"could not check", Capability{Status: Unknown, Reason: "permission_denied"}, false},
		{"never implemented", NotImplemented("windows"), false},
		{"zero value", Capability{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cap.RootKeyPermitted(); got != tc.permit {
				t.Fatalf("RootKeyPermitted() = %v, want %v", got, tc.permit)
			}
		})
	}
}

// The zero value must be the safe one. A Capability that nobody filled in has
// to mean "we do not know", never "there is nothing here" — otherwise every
// unset struct silently becomes a claim about somebody's hardware.
func TestTheZeroValueIsNotAClaimOfAbsence(t *testing.T) {
	var c Capability
	if c.Status == Absent {
		t.Fatal("an unfilled Capability claims the machine has no hardware")
	}
	if c.RootKeyPermitted() {
		t.Fatal("an unfilled Capability permitted a root key")
	}
}

// An unimplemented platform must be Unknown, not Absent. This is the exact
// defect being fixed: three signers in this package answer a hardcoded false,
// which reads downstream as "no hardware" on machines that certainly have it.
func TestNotImplementedIsUnknownRatherThanAbsent(t *testing.T) {
	c := NotImplemented("linux")
	if c.Status != Unknown {
		t.Fatalf("unimplemented platform reported %q — it must be unknown", c.Status)
	}
	if !c.NeedsHumanReview() {
		t.Fatal("an unimplemented platform should be reviewable, since that is how we learn it exists")
	}
	// The wording matters as much as the status: this string may be shown to
	// somebody deciding whether their machine is at fault.
	if !strings.Contains(c.Detail, "says nothing about") {
		t.Fatalf("the detail could be read as a verdict on the machine: %q", c.Detail)
	}
}

// Unknown is what gets asked about; a settled answer is not.
func TestOnlyUnknownAsksForReview(t *testing.T) {
	for _, s := range []Status{Usable, Present, Absent} {
		if (Capability{Status: s}).NeedsHumanReview() {
			t.Fatalf("%q asked for human review, but it is a settled answer", s)
		}
	}
	if !(Capability{Status: Unknown}).NeedsHumanReview() {
		t.Fatal("unknown did not ask for review, so we would never learn about the device")
	}
}

// Nothing we render may tell somebody their hardware is missing when we simply
// did not look.
func TestUnknownNeverReadsAsAbsence(t *testing.T) {
	got := Unproven("permission_denied", "/dev/tpmrm0: permission denied").String()
	if strings.Contains(got, "no hardware") {
		t.Fatalf("an undetermined result renders as absence: %q", got)
	}
	if !strings.Contains(got, "could not determine") {
		t.Fatalf("an undetermined result does not say so: %q", got)
	}
}
