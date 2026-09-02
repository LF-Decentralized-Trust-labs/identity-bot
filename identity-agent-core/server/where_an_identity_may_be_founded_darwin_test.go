//go:build darwin && !ios

package server

import "testing"

// macOS, named rather than inferred from the switch next door.
//
// Modelled on how this package already tests build-tag-selected behaviour —
// capability_darwin_test.go and capability_windows_test.go do exactly this. Its
// honest limit is that it runs only on a Mac, which is where this work happens
// and where four root identities were founded before the check existed.
func TestAMacMayNotFoundAnIdentity(t *testing.T) {
	v := foundingVerdictForThisPlatform()
	if v.Permitted {
		t.Fatalf("a Mac may not found an identity: %+v", v)
	}
	if v.Platform != "macos" {
		t.Fatalf("a Mac should say so, and says %q", v.Platform)
	}
}
