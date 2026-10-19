// Package buildmode records, at build time, whether this is a production or a
// development build, and never lets that change at runtime.
//
// The mode is set with a linker flag and defaults to production:
//
//	go build -ldflags "-X identity-agent-core/buildmode.rawMode=dev"
//
// It is deliberately NOT read from an environment variable or a config file. A
// production binary therefore cannot be turned into a development one after it
// ships — the only way to get a development build is to build one. That is the
// property the developer-mode trust model rests on: a production build trusts
// production release keys only, and a development build carries development
// release keys only, so the two cannot verify each other's software updates. As
// the rest of developer mode is built, the same build-time separation extends to
// peers and sealed data; this package is the foundation they all build on, but
// today it gates the software-update trust anchor only.
//
// The compiled mode is a convenience and a visible label, not the security
// boundary itself. The boundary is the separate trust anchors each mode selects
// (see package update's release key ids). The mode lets the core pick the right
// anchor and makes a development build legible; it does not, on its own, keep a
// recompiled build out of production — the trust anchors do that.
package buildmode

import "fmt"

// Build modes. Production is the default, so a build that says nothing is safe.
const (
	Prod = "prod"
	Dev  = "dev"
)

// rawMode is overridden at link time via -ldflags "-X ...buildmode.rawMode=dev".
// Nothing else writes it.
var rawMode = Prod

// mode is resolved once, at package initialisation, from rawMode. An unknown
// value stops the process immediately rather than being silently treated as
// production — a misconfigured build must fail loudly at startup, not ship.
var mode = mustResolve(rawMode)

func mustResolve(raw string) string {
	m, err := resolve(raw)
	if err != nil {
		panic(err)
	}
	return m
}

// resolve validates a raw mode string. Separated out so it is testable without
// rebuilding the binary with a different linker flag.
func resolve(raw string) (string, error) {
	switch raw {
	case Prod, Dev:
		return raw, nil
	default:
		return "", fmt.Errorf("buildmode: unknown build mode %q; must be %q or %q", raw, Prod, Dev)
	}
}

// Mode returns the build mode, Prod or Dev.
func Mode() string { return mode }

// IsDev reports whether this is a development build.
func IsDev() bool { return mode == Dev }

// IsProd reports whether this is a production build.
func IsProd() bool { return mode == Prod }
