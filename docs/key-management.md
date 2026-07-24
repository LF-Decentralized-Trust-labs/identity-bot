# Key Management — One Root of Trust

This document states the Identity Agent's key-management model in one place.
It applies identically to desktop and mobile: the same client code generates
keys, and the same embedded core derives HD keys.

## The mnemonic is the sole root of trust

The BIP39 mnemonic generated at onboarding (and shown once to the user as the
recovery phrase) is the ONLY secret a user must safeguard. Everything else is
derived from it or recoverable with it:

```
mnemonic (user-held, platform secure storage via SecureKeyStore)
  └─ BIP39 seed (64 bytes, standard PBKDF2-HMAC-SHA512)
      ├─ root identity AID keys        (client layer: crypto/keys.dart)
      └─ core root seed (handed off once via POST /api/keystore/root-seed)
          └─ SLIP-0010 HD derivation m/44'/0'/0'/index'/key'
             (backup.DerivePairwiseSeed)
              ├─ pairwise contact relationship keys
              ├─ per-site login relationship keys
              ├─ asset signing keys
              ├─ invocation-log (audit) signing key
              └─ credential-vault encryption key (HKDF from the same root)
```

At identity creation — and again on recovery by phrase — the client computes
the BIP39 seed and posts it to its local core (`/api/keystore/root-seed`,
local-owner only, idempotent, refuses to replace a different established
seed). The core never sees the mnemonic words and no endpoint ever returns
the seed.

**Recovery = re-enter the phrase.** On a new device the same handoff reseats
the core's root, and every derived key re-derives. Backup archives restore
*state* (contacts, KEL, credentials, settings) and also carry the root seed
as a belt-and-suspenders copy — but archives are a convenience, not key
escrow; the phrase alone is sufficient for key material.

## What KERI does and does not govern

KERI governs *events*: inception, rotation, the KEL, signatures, and their
verification. It deliberately does not prescribe how implementations generate,
derive, or store private keys — that is key management, and this document is
its specification for this codebase. Hierarchical derivation of per-relationship
AIDs from one root (BIP32/SLIP-0010) is an implementation choice that keeps
thousands of pairwise keys recoverable from a single secret; each derived AID
is still an ordinary KERI AID with its own KEL.

## At-rest protection (defense in depth, never part of recovery)

The core's root seed is stored in `secureenclave/root_seed.key`, wrapped under
a platform hardware key where one is usable (Secure Enclave on Apple silicon;
TPM/StrongBox/TEE behind the same seam later). Hardware wrapping is a
device-local confidentiality layer only: losing the device or its secure
element never loses anything the phrase (or an archive) cannot restore, and no
hardware element is ever the sole holder of unrecoverable material.

A core that mints keys before any handoff (headless or development setups that
never complete interactive onboarding) falls back to a random device-local
root, logged loudly as a warning — those HD keys are recoverable only from
backup archives, not the phrase. Interactive onboarding always performs the
handoff, so user-facing installs never operate in this mode.
