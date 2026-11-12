// Package lockgate is what makes a logged-out identity unusable: a key that only
// a passing authentication result releases, and the two sealed places that key
// rests while it is on the device (ADR-074).
//
// THE SHAPE. A profile's secret (a phone's root seed, a desktop's controller key)
// is sealed under GK, a 32-byte key, and the sealed bytes are then wrapped by the
// platform's hardware key:
//
//	envelope(profile) = HardwareWrap_device( GateSeal_GK(profile)( secret ) )
//
// GK itself rests in two items, both under the hardware key with no person
// needed to be present:
//
//   - the GATE COPY, made when the profile is made and kept while it exists,
//     read only by Gate.Release after a passing result. All a LOCKED identity has;
//   - the DEVICE-HELD COPY, made at log-in and deleted at log-out, so a phone
//     whose operating system killed the app reopens by reading it, with nobody
//     present.
//
// WHAT THIS DOES NOT DO, AND THE LOCK SAYS SO. While the authentication provider
// is a placeholder that answers 80 for everybody, no secret exists that only the
// person has. A copied profile directory opens nothing; code running as the same
// user on the unlocked device can still unwrap the gate copy and ask the gate.
// LockClass says which of those is true, derived and never inferred, so no
// screen, route or log claims protection that is not there.
package lockgate
