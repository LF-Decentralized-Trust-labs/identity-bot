# ADR-037: One KERI engine on every platform

**Status:** Accepted
**Date:** 2026-08-18
**Supersedes:** ADR-004 (in part — the FFI bridge half), ADR-015 (in part — the mobile engine), ADR-001 (in part — mobile key management)
**Related:** ADR-006 (Standardized Topology)

## Context

A phone ran a KERI engine of its own, written in Rust and reached over an FFI
bridge. A computer ran the Go core. Two implementations of one protocol, assumed
to behave alike.

They did not. The Rust inception took a mnemonic parameter and ignored it —
`incept_aid(name: String, _code: String)` — and called a constructor that
generated a fresh random keypair. The key lived in an in-memory map. So on a
phone:

- an identity could not be recovered from its recovery phrase, because the
  phrase never produced the key in the first place, and
- an identity did not survive the app restarting, because nothing outside memory
  held it.

Both are properties the product is *for*. Neither failed loudly; the phrase was
accepted, an identity appeared, and it was simply a different one.

## Decision

**There is one KERI engine — `keri-go` — and every platform uses it.** A
computer spawns it as a process; a phone embeds it via `gomobile`. Both reach it
over HTTP through `LocalCoreKeriService`, named for what it talks to rather than
the kind of computer it runs on.

The Rust bridge, its generated bindings, its build steps and its CI are removed
rather than repaired.

## Why removal rather than a fix

The bug was a symptom. A second implementation on one platform is a place for
exactly this kind of divergence to hide, and this divergence was the one that
mattered most — an identity that cannot be recovered is not an identity anybody
should rely on.

Fixing the Rust inception would have restored the property and kept the hiding
place. Nothing needed two engines: the Go core already ran on the phone, for
persistence, and was already the engine everywhere else.

## Consequences

- Mobile KERI is the same code, exercised by the same tests, as desktop.
- A recovery phrase produces the same identity on any platform. This was checked
  by hand when the callers were switched — a fixed phrase founded an identity
  whose public key was the key that phrase produces, and the same identity came
  back after the process was killed and restarted. No automated test covers it
  yet, and one should: it is the property this whole change exists to protect.
- Mobile builds need no Rust toolchain — no `rustup`, no `cargo`, no bridge
  codegen. Build times and the number of ways a build can fail both drop.
- The `flutter_rust_bridge` dependency, the `rust/` tree, the generated Dart
  bindings, the iOS link flags and the Rust CI steps are gone.
- Android was pinned to `arm64-v8a` because the Rust library was arm64-only.
  That constraint no longer has a cause; whether to widen it is a separate
  decision and is not made here.
- `MobileOnDeviceKeriService` and `MobileRemoteKeriService` are removed. Several
  screens tested for the former to decide whether the device held its own keys;
  every device does now, so those tests are gone rather than inverted, which
  leaves the views they gated exactly as they have behaved since the engine
  changed.

## What this does not decide

Whether the post-quantum work keeps a Rust component. `pqc-poc-rust/` is a
separate proof of concept with its own consumers and is untouched by this — it
is not a KERI engine, and removing a KERI engine is the whole of what this
records.

> **Answered 2026-08-17: it does not.** The crate is deleted. Two things settled
> it. It had one consumer — `drivers/keri-core/pqc/mldsa_crypto.py`, which shelled
> to it for ML-DSA-65 and now reaches the Go core instead — and it could not build:
> `Cargo.toml` declared binaries at `src/bin/c4roundtrip.rs` and
> `src/bin/pqc_mldsa_cli.rs`, neither of which was ever committed. So the "own
> consumers" this section assumed were one consumer and a broken build.
>
> The post-quantum work loses nothing. ML-DSA-65 and ML-KEM-768 come from
> `github.com/cloudflare/circl` — pure Go, `CGO_ENABLED=0` clean, so it links under
> `gomobile`. That removes the reason the Rust fallback existed at all: `liboqs-go`
> would not link on mobile, and circl does. One library now covers all five
> platforms instead of liboqs on desktop and RustCrypto on mobile.
>
> One thing genuinely narrows. ML-DSA is no longer cross-checked against a second
> implementation — the Python reference takes it from the Go core rather than
> computing it independently. The golden vectors still prove the CESR wire framing
> agrees across engines, which is what they were built to catch. Restoring the
> independent check wants a pure-Python ML-DSA, not a second native engine.
