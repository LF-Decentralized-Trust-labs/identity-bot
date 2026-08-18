# ADR-027: Hardware-Gated Signing Key Custody

**Status:** Accepted, with the implementation notes below corrected 2026-08-17.
The decision and its reasoning stand. Where this ADR says mobile signing happens in
a Rust bridge, or weighs adding a P-256 derivation code against "the Rust `keri_core`
bridge", that engine no longer exists — see "What changed since this was written" at
the end before relying on any implementation detail here.
**Date:** 2026-07-20
**Extends:** ADR-014 (Key Custody, Backend Server Mode, Migration, and Data Partitioning)

## Context

ADR-014 established that the BIP39 mnemonic is stored via `SecureKeyStore` (`flutter_secure_storage`, backed by platform secure storage — Keychain, Android Keystore, DPAPI, libsecret) and that signing derives the Ed25519 key pair from that mnemonic and signs directly in software (`ed25519_edwards` on desktop; the Rust bridge on mobile).

A review of the actual implementation found that `SecureKeyStore` configures no access-control policy at all — `loadMnemonic()` is a plain read that returns the mnemonic to any caller in the app process, gated only by the device being unlocked. There is no requirement that a live authentication event (biometric, passcode) occur at the moment of access. This means an automated or supply-chain-compromised code path within the app can read the mnemonic silently, with no user-visible event.

> **Amended 2026-08-02 — a fact in this paragraph was wrong, and the decision stands anyway.**
>
> `keripy` 1.1.17 **does** support NIST P-256. It defines `ECDSA_256r1_Seed` (`Q`),
> `ECDSA_256r1_Sig` (`0I`) and both verkey codes (`1AAI`, `1AAJ`), with working sign and verify
> paths. The sentence below names only Ed25519 and secp256k1, which understated what the
> library can do and made the constraint look like a hard protocol limit when it is not.
>
> Two things changed as a result, and neither reverses this ADR.
>
> First, the real constraint is narrower and lives elsewhere: of the implementations shipped
> here, only the Python driver speaks P-256. The Rust CESR stack has no P-256 code point, so a
> P-256 verkey fails to *parse* rather than to verify — a framing-layer error rather than a
> clean rejection. P-256 *indexed* signature codes are also a `keripy` extension absent from the
> published CESR specification, so a P-256 key in a multi-signature group would produce
> signatures a conformant third party rejects.
>
> Second, and more decisive: ECDSA requires a fresh secret number per signature, and one that
> repeats — or is merely biased — discloses the private key. That failure has occurred in
> shipped secure hardware on this exact curve, and a biased nonce produces signatures that
> verify perfectly, so nothing in the system would report it. EdDSA derives its nonce
> deterministically and has none to leak.
>
> The choice to have hardware **wrap** the signing key rather than **hold** it therefore rests
> on a stronger argument than the one originally given: not that the curve cannot be used, but
> that using it would trade a failure mode we can reason about for one we could not detect.

Separately, this was found to be a curve/hardware mismatch, not a configuration gap: the KERI signing key is Ed25519 (with `secp256k1` also supported by `keripy`'s derivation codes — see `keri/core/coring.py`'s `MtrDex`). None of the platform secure-key facilities available to this project (Apple Secure Enclave, Android StrongBox/TEE, Windows TPM 2.0 via CNG) can generate or hold either of those curves as a true non-extractable hardware-resident key — all three standardize on NIST P-256 (secp256r1) for hardware-backed key generation and signing. This is not a project oversight; it reflects Ed25519's own design goals (deterministic signing to eliminate the ECDSA weak-nonce key-recovery class of bugs, and avoidance of NIST-curve parameter-generation trust concerns) predating and diverging from what consumer secure-element vendors chose to implement in silicon. Switching the KERI root key itself to a hardware-native curve is tracked separately as a rejected-for-now alternative (see "Alternatives Considered").

## Decision

Add a hardware-backed access gate in front of the existing software-Ed25519 signing path, without changing the KERI key material, curve, or the BIP39 recovery model.

### Layer 1 — Hardware-Wrapped Mnemonic (this ADR, buildable now)

1. At inception, in addition to today's `SecureKeyStore` write, generate a P-256 key pair inside the platform's real secure element:
   - iOS/macOS: Keychain `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` (or `CryptoKit.SecureEnclave.P256.KeyAgreement.PrivateKey`).
   - Android: `KeyGenParameterSpec` requesting EC/P-256, `setIsStrongBoxBacked(true)` where available (falls back to TEE when not).
   - Windows: CNG `NCryptCreatePersistedKey` against the Microsoft Platform Crypto Provider (TPM 2.0), ECDSA P-256.
   - **Deliberately no per-use OS authentication requirement on this key** (no `kSecAccessControlBiometryCurrentSet` / `setUserAuthenticationRequired`). See "Why no OS-level biometric flag" below — this is an intentional architecture choice, not an omission.
2. Use that hardware key to wrap (encrypt) the mnemonic — ECDH between the enclave key and an ephemeral key, deriving a symmetric key that encrypts the mnemonic; only the ciphertext is persisted where `SecureKeyStore` stores it today.
3. The derived Ed25519 key pair continues to be computed in software from the unwrapped mnemonic exactly as ADR-014 describes, and should be discarded immediately after use. (Dart does not guarantee secure memory zeroing on garbage collection — this residual exposure window is a known, accepted limitation of any software-Ed25519 approach on these platforms; see Consequences.)
4. Platforms/configurations without a usable secure element (older Android devices, desktops without TPM 2.0, Linux without a configured TPM) fall back to ADR-014's existing behavior unchanged — this ADR is additive, not a hard requirement that blocks the app from functioning.

### Layer 2 — `AuthProvider` as the Sole Authorization Gate (depends on the `AuthProvider` interface, not yet built)

The decision of *whether to unwrap the mnemonic at all* for a given signing request is owned entirely by the configured `AuthProvider` — not by a hardcoded OS-level check. `AuthProvider` evaluates whatever combination of factors its own implementation defines (device binding, recency of prior verification, anomaly signals, an active duplicity flag on the KEL, and — at its own discretion, not as an externally imposed requirement — a fresh biometric or passcode check via the same platform APIs Layer 1 would otherwise have used directly). Only once `AuthProvider` authorizes the request does the app proceed to Layer 1's hardware unwrap.

**Why no OS-level biometric flag (this is the point, not a gap):** an OS-enforced per-use biometric requirement on the P-256 key would force an unconditional prompt on every signature regardless of what `AuthProvider` has already established — exactly the redundant, un-unified gate this design avoids. `AuthProvider` is the single place authorization policy lives; it may itself choose to invoke a platform biometric check as one of its inputs, but that is `AuthProvider`'s decision to make, on its own criteria, not a fixed requirement bolted onto the key.

**Hard rule:** there must be exactly one code path capable of invoking Layer 1's unwrap operation, and it must always run through `AuthProvider`'s authorization check first. No other call site may reach the unwrap function directly. This is an architectural discipline requirement, not something the platform enforces for us — see Consequences for what that tradeoff means concretely.

`AuthProvider`'s interface and any specific scoring/factor model behind a given implementation are out of scope for this ADR.

## Alternatives Considered

**A — Status quo (ADR-014 unchanged).** Rejected as insufficient on its own: no live-authentication requirement at all today; an automated read of `SecureKeyStore` succeeds silently.

**C — Hardware-native root key (add a P-256 derivation code to KERI/CESR end to end).** Not rejected outright, but deferred as a separate, larger, opt-in future path. This is a legitimate extension of CESR's algorithm-agile derivation-code system (the same mechanism that already supports both Ed25519 and secp256k1) — it would not violate the protocol. But it requires: (1) matching support in both `keripy` (desktop) and the Rust `keri_core` bridge (mobile) — not yet verified for the latter; (2) every witness/verifier that checks this project's signatures, including any not under this project's control, to recognize the new code; (3) giving up the BIP39 mnemonic recovery model entirely, since a true hardware-native key has no seed a human can write down or re-enter — recovery would need to move to a delegate/successor-key or witness-based model instead. This tradeoff — a portable, human-recoverable seed phrase vs. a key that can never leave one specific piece of hardware — is a product decision, not just an engineering one, and is left open for a future ADR if pursued.

## Consequences

- Closes the concrete gap that exists today: silent, automated extraction of the mnemonic without any live user-presence check — conditional on the "exactly one code path, always through `AuthProvider`" rule actually holding across the codebase. This is now a software/architectural guarantee rather than an OS/silicon-enforced one: with the biometric flag, even a maliciously modified build of the app could not skip the check, because Apple/Google's hardware enforces it unconditionally; without the flag, that guarantee depends on `AuthProvider`'s own code being the sole reachable path to the unwrap function. This tradeoff is deliberate — see Layer 2 rationale — but should be understood plainly as moving the enforcement point from hardware to disciplined software architecture.
- Does not eliminate the narrow window where the derived Ed25519 private key exists in ordinary process memory during an active signing operation — this remains true on every platform for as long as the KERI signing key is Ed25519, because no available secure element can perform Ed25519 math internally. Only Alternative C removes this window, and only on the specific device where the hardware-native key lives.
- No change to the BIP39 recovery UX, the KERI curve, or any witness/verifier compatibility — this is purely an access-control addition in front of the existing signing path.
- Devices without a usable secure element are unaffected and continue to work exactly as ADR-014 describes; this is a strict improvement where hardware is available, not a new requirement.
- Layer 2 is not implementable until the `AuthProvider` interface exists; this ADR's Layer 1 (hardware wrap, no OS-forced biometric) does not depend on it and can ship independently, but the "sole gate" model only takes effect once `AuthProvider` exists and is wired as the only caller of the unwrap function — until then, this codebase should not call the unwrap function via any other path either, since a default "call it whenever needed" pattern before `AuthProvider` exists would defeat the intent of this ADR.
- No interaction with backup/recovery: the backup archive's encryption key is derived from the portable root seed (see the backup and recovery design), not from this device-local hardware wrap — a device-bound key was explicitly considered and rejected as a backup mechanism there, for the same reason it would defeat cross-device recovery. **Implementation note for whoever builds backup export:** the backup export step must call `SecureKeyStore.loadMnemonic()` (which unwraps) to obtain the plaintext mnemonic for the archive — never read the raw stored value directly, which after this ADR may be the `hw1:`-prefixed wrapped ciphertext rather than the mnemonic itself.

## References

- [ADR-014](014-key-custody-migration-and-data-partitioning.md) — existing key custody, `SecureKeyStore`, software Ed25519 signing
- [ADR-015](015-mobile-keri-service-architecture.md) — mobile KERI service architecture, Rust bridge
- `identity_agent_ui/lib/services/secure_key_store.dart` — current mnemonic storage implementation
- `drivers/keri-core/` — pinned `keripy` version and its `MtrDex` derivation codes (`Ed25519`, `Ed25519_Seed`, `ECDSA_256k1`)

## What changed since this was written (2026-08-17)

Nothing here about hardware key custody has changed. What changed is the engine
underneath it, so three implementation details in the text above are now wrong.

- **"the Rust bridge on mobile"** (Context). Mobile no longer signs through a Rust
  bridge. There is one KERI engine on every platform — the Go core — which desktop
  spawns as a process and mobile embeds via `gomobile`. Read that clause as "the
  embedded Go core on mobile". Software Ed25519 signing from the mnemonic is
  unchanged; only where it runs is different.

- **"The Rust CESR stack has no P-256 code point"** (the quoted note). There is no
  Rust CESR stack. The observation it was making still holds and is now simply about
  the Go core: P-256 is not among the derivation codes in use, so only the Python
  driver speaks it.

- **Alternative C's first prerequisite** — "matching support in both `keripy`
  (desktop) and the Rust `keri_core` bridge (mobile) — not yet verified for the
  latter" — now reads as matching support in `keripy` and the Go core. That is a
  smaller prerequisite than it was, because it is one implementation on both
  platforms rather than two that must agree. The rest of alternative C is unaffected:
  the ecosystem-recognition and mnemonic-recovery tradeoffs are what make it a product
  decision, and those are untouched.

The reference to ADR-015 below describes the mobile architecture as it was. See
[ADR-037](037-one-keri-engine-on-every-platform.md) for the engine that replaced it,
and why two implementations of one protocol turned out not to behave alike.
