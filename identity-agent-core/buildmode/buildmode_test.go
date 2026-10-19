package buildmode

import "testing"

func TestResolveAcceptsTheTwoKnownModes(t *testing.T) {
	for _, m := range []string{Prod, Dev} {
		got, err := resolve(m)
		if err != nil {
			t.Fatalf("resolve(%q) returned error: %v", m, err)
		}
		if got != m {
			t.Fatalf("resolve(%q) = %q, want %q", m, got, m)
		}
	}
}

func TestResolveRejectsAnythingElse(t *testing.T) {
	// An unknown value must be an error, not a silent fall-through to a default.
	// A build that mis-sets the mode should fail at startup, where it is visible,
	// rather than run as production (or as nothing) and be found later.
	for _, bad := range []string{"", "production", "development", "PROD", "staging", "0"} {
		if _, err := resolve(bad); err == nil {
			t.Fatalf("resolve(%q) returned no error; an unknown mode must be refused", bad)
		}
	}
}

func TestDefaultBuildIsProduction(t *testing.T) {
	// With no linker flag, a build is production. This is the safe default: a
	// build that says nothing must not be treated as a development build.
	if !IsProd() || IsDev() {
		t.Fatalf("default build mode = %q; want production", Mode())
	}
	if Mode() != Prod {
		t.Fatalf("Mode() = %q, want %q", Mode(), Prod)
	}
	if Marker() != "" {
		t.Fatalf("production Marker() = %q, want empty", Marker())
	}
}
