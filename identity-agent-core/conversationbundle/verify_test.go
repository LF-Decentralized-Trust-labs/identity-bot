package conversationbundle

import (
	"strings"
	"testing"
)

// The bundles a real Identity Agent exports, genuine and altered, are checked
// in the server's tests (a_conversation_is_exported_test.go), which make them.
// These cover what needs no Identity Agent at all.

func TestNothingIsVerifiedWithoutABundle(t *testing.T) {
	if r := Verify(nil); r.Verified || len(r.Faults) == 0 {
		t.Fatalf("no bundle verified: %+v", r)
	}
}

func TestABundleOfAnotherFormatIsRefused(t *testing.T) {
	r := Verify(&Bundle{Format: "something-else", Conversation: "c_x", Root: "E"})
	if r.Verified || len(r.Faults) != 1 || !strings.Contains(r.Faults[0].Why, Format) {
		t.Fatalf("a bundle of another format: %+v", r)
	}
}

func TestAnEmptyBundleProvesNothing(t *testing.T) {
	r := Verify(&Bundle{Format: Format, Conversation: "c_x", Root: "Eroot"})
	if r.Verified {
		t.Fatal("a bundle with no key logs, entries or log verified")
	}
	if len(r.Trusts) == 0 {
		t.Fatal("the report does not say what it trusts")
	}
}

func TestReadRefusesWhatAnExportNeverWrites(t *testing.T) {
	if _, err := Read([]byte(`{"format":"` + Format + `","unchecked":"anything"}`)); err == nil {
		t.Fatal("a bundle with a field an export does not write was read")
	}
	if _, err := Read([]byte(`{"format":"` + Format + `"}{"format":"` + Format + `"}`)); err == nil {
		t.Fatal("two bundles were read as one")
	}
	if b, err := Read([]byte(`{"format":"` + Format + `","conversation":"c_x"}`)); err != nil || b.Conversation != "c_x" {
		t.Fatalf("a well-formed bundle was not read: %v", err)
	}
}
