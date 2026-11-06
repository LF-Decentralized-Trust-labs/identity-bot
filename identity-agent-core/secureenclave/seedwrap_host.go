package secureenclave

import (
	"bytes"
	"fmt"
	"sync"
)

// A seed wrapper that the app supplies, for the platform where the hardware
// cannot be reached from Go.
//
// Android's Keystore is a Java API. Go has no path to it, which is why the app
// reports what the Keystore can do (capability_android.go) and why the key that
// wraps the seed has to be driven from the app as well. The core still decides
// what the answer means:
//
//   - the host's wrapper counts as hardware protection ONLY while the key
//     protection the app declared is proven usable, so an app cannot make a
//     software keystore look like StrongBox or a TEE by registering a wrapper;
//   - its scheme cannot be "none" or the sealed-volume scheme, either of which
//     would make the envelope claim a protection that is not the Keystore;
//   - whatever it returns is checked by storeSeedAs like any other wrapper: the
//     seed is not in the output, and the output opens back to the seed.
//
// Same shape as DeclareHardwareKeyProtection: the app registers before the
// server starts, and an app that registers nothing has no wrapper, said plainly.

// SeedWrapHost is what an app implements to wrap the root seed under a key it
// holds in the platform's hardware. On Android: an AES-256-GCM key in the
// Keystore, in StrongBox where the phone has it and in the TEE otherwise, never
// exportable, with no user-authentication requirement because the agent runs
// without a person present.
type SeedWrapHost interface {
	// Available reports whether the key exists or can be made, right now.
	Available() bool
	// Scheme names the wrap format and which hardware held the key, for example
	// "android-keystore-strongbox-aes256gcm" or "android-keystore-tee-aes256gcm".
	// It is recorded in the envelope, and it is how a seed made on one kind of
	// hardware is recognised as such later.
	Scheme() string
	Wrap(plain []byte) ([]byte, error)
	Unwrap(blob []byte) ([]byte, error)
}

var (
	seedWrapHostMu sync.RWMutex
	seedWrapHost   SeedWrapHost
)

// DeclareSeedWrapHost registers the app's wrapper. Called through mobilecore
// before the server starts. Passing nil removes it.
func DeclareSeedWrapHost(h SeedWrapHost) {
	seedWrapHostMu.Lock()
	seedWrapHost = h
	seedWrapHostMu.Unlock()
}

func declaredSeedWrapHost() SeedWrapHost {
	seedWrapHostMu.RLock()
	defer seedWrapHostMu.RUnlock()
	return seedWrapHost
}

// hostedSeedWrapper is the app's wrapper as the seam sees it.
type hostedSeedWrapper struct{ host SeedWrapHost }

// declaredHostSeedWrapper is the wrapper for whatever the app registered, or nil
// when it registered nothing.
func declaredHostSeedWrapper() SeedWrapper {
	h := declaredSeedWrapHost()
	if h == nil {
		return nil
	}
	return hostedSeedWrapper{host: h}
}

func (w hostedSeedWrapper) Scheme() string { return w.host.Scheme() }

func (w hostedSeedWrapper) schemeIsHonest() bool {
	s := w.host.Scheme()
	return s != "" && s != seedWrapNone && s != SealedVolumeScheme
}

// Available is true only when the app says its key works AND the app has proven
// the phone's key protection usable. The second half is the core's own check on
// the first: a wrapper cannot be hardware on a phone whose hardware the app
// itself did not prove.
func (w hostedSeedWrapper) Available() bool {
	return w.schemeIsHonest() && detectCapability().RootKeyPermitted() && w.host.Available()
}

func (w hostedSeedWrapper) Wrap(plain []byte) ([]byte, error) {
	if !w.Available() {
		return nil, fmt.Errorf("the app's seed wrapper is not usable")
	}
	return w.host.Wrap(plain)
}

func (w hostedSeedWrapper) Unwrap(blob []byte) ([]byte, error) {
	if w.host == nil || !w.schemeIsHonest() {
		return nil, fmt.Errorf("the app's seed wrapper is not usable")
	}
	return w.host.Unwrap(blob)
}

// phoneUnwrappedReason is the one reason a phone may hold a root identity's seed
// unwrapped: the app that is running predates the wrapper and registered none.
// An app that registered a wrapper gets no such allowance, so a phone whose
// wrapper cannot work (no hardware Keystore) is refused rather than excused.
func phoneUnwrappedReason(hostDeclared bool) string {
	if hostDeclared {
		return ""
	}
	return "android: this app registered no Keystore/StrongBox seed wrapper, " +
		"so this seed is stored unwrapped under the app's private storage"
}

// A wrapped blob must not carry the seed it is supposed to hide. The
// sealed-volume scheme is the one exception and is identity on purpose.
func wrapLeaksTheSeed(scheme string, blob, seed []byte) bool {
	return scheme != SealedVolumeScheme && bytes.Contains(blob, seed)
}
