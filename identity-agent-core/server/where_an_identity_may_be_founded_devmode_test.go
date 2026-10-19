package server

import "testing"

// A development build may found an identity on a machine that cannot attest; a
// production build may not. The decision is tested directly here because the
// build mode is fixed per test binary, so the handler-level path (the existing
// refusal tests in this package) exercises only the production branch.
func TestFoundingPermittedReflectsTheBuildRealm(t *testing.T) {
	cannotAttest := foundingVerdict{Permitted: false, Platform: "macos", Why: cannotProveItsSoftware}
	canAttest := foundingVerdict{Permitted: true, Platform: "ios"}

	if foundingPermitted(cannotAttest, false) {
		t.Fatal("a production build must refuse founding on a machine that cannot attest")
	}
	if !foundingPermitted(cannotAttest, true) {
		t.Fatal("a development build must allow founding on a machine that cannot attest")
	}
	if !foundingPermitted(canAttest, false) {
		t.Fatal("a machine that can attest must be allowed to found in any build")
	}
	if !foundingPermitted(canAttest, true) {
		t.Fatal("a machine that can attest must be allowed to found in a development build too")
	}
}
