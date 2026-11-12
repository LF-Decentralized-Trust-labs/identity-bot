# ADR-074: A Logged-Out Identity's Keys Are Unusable Until Its Owner Passes the Authentication Provider

**Status:** Proposed (2026-11-11)
**Amends:** ADR-006 (marks "Computer only" on your own computer, and "your own computer" as a place for keys, withdrawn by this ADR on 2026-11-11)
**Date:** 2026-11-11
**Deciders:** to be decided; nothing is built on this yet
**Builds on:** ADR-006 as amended in this same change (a controller is a third topology; a desktop never holds a root; `where_an_identity_may_be_founded_*.go`, `foundingVerdictForThisPlatform`), ADR-027 (hardware-gated signing key custody), ADR-028 (what a machine can protect a key with), ADR-039 (a backup is of an identity, not of an installation)

---

## Context

An Identity Agent app can hold more than one identity on a device, so one person's phone may carry a parent's identity and a child's. One of them is logged in at a time. The others are **logged out**.

Today a logged-out identity is only marked. The app writes a `locked` file in the identity's profile directory, stops the core, and asks the operating system to prove someone is there before it deletes the file and starts the core again. Three things are true of that, and the ADR exists because each is easy to misread as protection:

1. **The marker is not a lock.** Anyone who deletes the file and starts the core has the identity. The seed (on a phone) is readable by anything that asks the platform's wrapper, which asks for no authentication on any platform.
2. **Switching does not mark the identity it leaves.** The app locks on an explicit log-out only, so an identity left behind by a switch looks logged in.
3. **The wrapping key belongs to the device, not to the identity.** iOS has one Secure Enclave key, Windows one TPM key, Android one Keystore key; macOS holds a blob per wrap. None needs a person to be present. That is deliberate: a phone's core is killed by the operating system routinely and must answer again without anyone there.

Separately, ADR-028 records that the seed's at-rest wrapper was missing on every platform but iOS, and `seedwrap.go` records that wrappers now exist for iOS, macOS, Windows and Android. The statement "the seed is stored in the clear on every platform but iOS" is therefore no longer true of the code, but its replacement is not "every seed is protected" either. What is still open on each platform is in section 3.

### What a person must pass

The only thing that may open a logged-out identity is a **successful log-in through the authentication provider** (`identity-agent-core/authprovider`): a fresh, measured score of at least `permission.DefaultMinimumScore` (80). It is not an operating-system face or fingerprint prompt, and it is not the device's screen lock. Those prove that someone is at the device, not who.

Today the provider is a placeholder. `authprovider.UntilHumanAuthenticationIsBuilt` returns `PlaceholderScore` (80) for everyone, so a person logs in by selecting their identity. This ADR designs the lock so that the day a real provider exists, nothing but the provider changes. It also states, in section 4, how little protection the placeholder gives.

### Platforms

An identity's keys live in one of two places (ADR-006):

- **A phone (iOS or Android) holds the root.** Its root seed derives every other key and the credential vault's key.
- **A Mac or Windows PC never holds a root.** ADR-006 described a "Computer only" topology on the user's own computer. **This ADR decides, on 2026-11-11, that it is withdrawn: a desktop is a controller or a backup target, never the root**, and amends ADR-006 in the same change to say so. The code enforces the decision: `foundingVerdictForThisPlatform` (`where_an_identity_may_be_founded_{darwin,windows,linux,other,ios,android}.go`) permits founding only on iOS, Android and an AMD SEV-SNP sealed machine. A Mac or PC is a controller: it holds a key of its own and acts under authority the root device granted. What is worth locking there is the device's **controller key**, not a seed.

A sealed black-box Identity Agent holds a root and is a separate target; it has no logged-in person and is not changed by this ADR. Linux desktop is not a supported place to run an Identity Agent app for now and is not designed here.

## Decision

### 1. An identity is locked when its owner logs out or switches away, and not when the app restarts

At most one identity on a device is open. **Logging out, and switching to another identity, each lock the identity being left.** An app killed or restarted by the operating system does not lock anything: a phone's core must keep answering. A lock is a state of the identity, recorded where the core reads it, and a locked identity's keys are unusable until a log-in (section 2) opens it.

### 2. The gate: a key the provider's answer releases

Each profile's secret is sealed in two layers:

```
envelope(profile) = HardwareWrap_device( GateSeal_GK(profile)( secret ) )
secret            = root seed (phone) | controller-key blob (desktop)
```

- **The hardware layer** is the wrapper each platform already has, now keyed per profile. It binds the file to this device. It needs no person to be present, so a phone core can answer after a restart.
- **The gate layer** seals the secret under `GK`, a 32-byte key (AES-256-GCM under `HKDF(GK, profile id)`). **`GK` is released only by the gate, and only for a passing provider result.** On the device `GK` rests only in the two sealed copies below: the gate's own, and, while logged in, the device-held copy, deleted at log-out.
- **The gate is one interface in the core**, `Gate.Release(profile, ProviderResult) (GK, error)`, where a `ProviderResult` carries the profile, level, score, time, a nonce and, on a desktop, the voucher. It releases only if the score is at least `permission.DefaultMinimumScore` and the result is fresh. A real provider replaces the placeholder behind `authprovider` without touching the envelope or the gate's callers.
- **A desktop's voucher is good for one log-in.** The root device signs `authprovider.CanonicalUnlockVoucherStatement`: the authentication statement under its own first line (`IA-UNLOCK-VOUCHER-V1`) with the log-in's nonce on the last line, so a voucher cannot be reused under a fresh nonce and a statement made for a request cannot be spent as a log-in. Spent nonces are kept in the profile's directory, so a core restart does not reopen the window.

  **The exact format** (pinned by `TestAnUnlockVoucherStatementHasOneFixedForm` in `identity-agent-core/lockgate`): the UTF-8 text below, lines joined by `\n`, no trailing newline, then signed Ed25519 by the root device's key and written as a CESR qb64 signature (the form `login.SignString` produces):

  ```
  IA-UNLOCK-VOUCHER-V1
  <agent AID>
  <controller identifier of the desktop>
  <level: an authprovider.Level, e.g. authenticated>
  <time, UTC, RFC 3339, e.g. 2026-11-11T09:30:00Z>
  <score, decimal integer>
  <the log-in's nonce, at least 16 characters>
  ```

  Test vector: for agent `EAgent`, controller `BController`, level `authenticated`, time `2026-11-11T09:30:00Z`, score `80`, nonce `0123456789abcdef0123`, and a root-device seed of 32 bytes of `0x07` (public key, base64, `6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=`), the signature is `0BB4IoJbFHyiLBuHxVETVS81OvwMc_7FNxSmsraaYotvenZaI16UUzzMiiskhd114Qb5-R3auaTWSfy0A-zAUl0F`. A change to any of this is a new first line, never an edit.
- **Changing the identity secret is journalled.** The new record and both keys are written down (under the hardware wrapper) before anything changes, and the change is then completed in a repeatable order: re-seal, write the record, write the device-held copy, delete the journal. A journal found at start is finished, never undone.
- **The recovery phrase and the backup credential key are sealed under `GK` too**, as the seed is: a locked identity neither reads nor writes them, and a change of the identity secret re-seals them with the seed.
- **`GK` rests in two items on a device, both under the platform's hardware key with no user-presence requirement (section 3).**
  - **The gate copy** is made when the profile is made, lasts as long as the profile, and is read only by `Gate.Release`, after a passing provider result. It is all that a **locked** identity has.
  - **The device-held copy** is made at log-in and **deleted at log-out**. A phone is killed by its operating system routinely, and the identity must reopen after the restart with nobody present (section 1), so the core reopens a **logged-in** profile by reading this copy, with no log-in step. A locked identity can be reopened only through the gate.
- **What this adds, and what it exposes, plainly.** *Locked* stops a copied profile directory or a deleted `locked` file from opening anything, because every copy of `GK` is under a key that does not leave the device. **It does not stop code running as the same user on the unlocked device**: while the provider is a placeholder, the key that seals the gate copy needs no person to be present, so such code can unwrap it and ask the gate (section 4). That is `lock_class` `app_only`. Once a real provider exists (`provider_bound`) the gate copy is unwrapped only with something the provider releases (section 3), and the device-held copy then differs from it in a way that matters: a locked identity has no copy that opens without the provider. *Logged in* exposes the device-held copy to anyone holding the unlocked device and to same-user code, which is what the seed already allows today; the copy is what lets a phone survive being killed, not a protection against the person at the device.
- **A logged-out identity vouches for nothing.** A desktop's score is vouched for by its person's root device (below). A phone whose identity is logged out holds no `GK`, so it cannot sign that voucher and its desktops stay locked. A locked identity is not available to its desktops until the person logs in on the phone.
- **Opening is the same everywhere.** The app runs the log-in through the provider, and on a pass calls an unlock route on the locked core. **The unlock route requires the local owner proof** (`LocalOwnerSecretHeader`, the same proof that lets the app stop a core), so a request without it is refused. Under `app_only` (section 4) any process running as the owner can read that proof, so this keeps out other users, other machines and web pages and does not keep out the owner's own code. The core asks the gate, unseals, **keeps the secret only in memory** and serves. **A locked core is started (or left) answering only a lock-state route and unlock** (and the route an app asks for the proof that a core holds the owner proof, before it sends it anything). It reads no seed.
- **A desktop's score is vouched for.** A machine may not score itself. The result a desktop's gate accepts is a `VouchedAuthentication` (level, time, score, `vouchedBy`) signed over that machine by the person's root device. If the root device cannot be reached, the desktop stays locked. That is the design, not a fault.
- **The envelope names its scheme and version**, so a reader can open an envelope written under an earlier scheme and an interrupted migration can resume (section 6).

**The phrase remains the way back from a lost key** (ADR-039, and invariant 2 in `seedwrap.go`): hardware and the gate are device-local layers, and a restore from the phrase makes a new profile with a new `GK` and a new envelope.

### 3. The seed at rest, and the controller key, on each platform

Every platform gets the same two layers. What differs is the hardware layer and what is still open. A platform's claim is a design claim until its probe has passed on a real device.

| Platform | Holds | Hardware layer | What is open today |
|---|---|---|---|
| **iOS** | root seed | Secure Enclave key in the keychain, accessible after first unlock, device only, no authentication requirement (`seedwrap_ios.go`) | Per-profile key tag; the gate layer. No other gap. |
| **Android** | root seed | the app's StrongBox or TEE Keystore key, supplied to the core through the host interface (`seedwrap_host.go`), no user-authentication requirement | The wrapper works only if the app registers the host; an app that does not cannot found an identity (refused, never stored unwrapped). A seed written before production builds refused unwrapped storage may be unwrapped; migration re-wraps it. A keystore without attestation is a probe, not a guess. |
| **macOS** | controller key | a Secure Enclave key blob the core holds itself (`seedwrap_darwin_sep.go`, build tag `sepblob`) | The wrapper exists only in a build with that tag. A build without it has none, and a production build then refuses to store a device-local seed. Only a build with the tag is a supported macOS build; a development build says in the status route that it is unwrapped. |
| **Windows** | controller key | a TPM RSA key through the Platform Crypto Provider (`seedwrap_windows.go`) | The wrapper has never been run on Windows. A secret already stored unwrapped is not re-wrapped without an explicit opt-in. Re-wrapping waits for the probe. |

**Where `GK` rests on each platform, and what each gives.** Both copies (section 2) rest in the same kind of place, sealed by a device hardware key with **no user-presence requirement**. A copied file or profile directory yields nothing on all four, because the hardware key does not leave the device. **Same-user code on the unlocked device is not stopped on any of them while the provider is a placeholder**, for a locked identity as well as a logged-in one. Every row is a design claim until its probe has passed on a real device.

| Platform | `GK` rests in (locked and logged in) | Same-user code gets | `provider_bound`: unwrapped only with |
|---|---|---|---|
| **iOS** | A keychain item, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, sealed by the profile's Secure Enclave key, no access-control prompt, so a background relaunch can read it. `ThisDeviceOnly` items are not in backups or transfers. | Nothing outside the app's own sandbox and keychain access group. Code inside the app can unwrap it. | The keychain item holds `GK` already encrypted under a key the provider releases, so the keychain alone opens nothing. |
| **Android** | A Keystore key per profile (StrongBox or TEE where present) with **no user-authentication requirement** and **unlocked-device-required**, sealing a file copy in the app's private storage. **A phone restarted while its screen is locked reopens the identity once the person unlocks the screen, not before.** | Nothing outside the app's UID. Code inside the app can unwrap it. | The stored file holds `GK` already encrypted under a key the provider releases, so the Keystore key alone opens nothing. |
| **macOS** | **A file in the profile directory wrapped by a Secure Enclave key blob the core holds itself**, as `seedwrap_darwin_sep.go` does (build tag `sepblob`). It is not a keychain item: the bare core is not proven to reach the keychain, and a probe (section 3, macOS) decides that before anything is moved there. | Any process of the same user that can read the file and drive the enclave key. Whether an unrelated same-user process is refused is a probe, and until it passes this is stated as "yes". | The file holds `GK` already encrypted under a key the provider releases, so the enclave key alone opens nothing. |
| **Windows** | A TPM RSA key per profile through the Platform Crypto Provider with **no authorization value**, sealing a file copy under the profile directory. | **Any process of the same user**: the TPM key has no authorization value, so anything running as the user can ask it to unwrap. Stated as "yes", not softened. | The TPM key's authorization value is derived from what the provider releases (`HKDF(released, "tpm-auth")`), so the TPM refuses without it and applies its own lockout. |

What "something the provider releases" is, and how a desktop obtains it, is the real provider's design and is not fixed here. Moving a profile from `app_only` to `provider_bound` re-seals the gate copy under it, as a migration step (section 6). Under `provider_bound` only the gate copy needs the provider. The device-held copy of a logged-in identity stays sealed by the device alone, so a phone the operating system has killed still reopens the identity that was logged in, with nobody present.

A production build refuses to store a root seed unwrapped on every platform it supports (`StoreIdentityRootSeed`, `StoreDeviceLocalSeed`), and a machine that cannot wrap says so rather than storing in the clear and reporting otherwise (ADR-028).

**The controller key on a desktop.**
- *macOS:* the blob is held by the core, so it is sealed under `GK` and a locked profile is ciphertext on disk.
- *Windows:* a Windows Hello key can only sign, and log-in is the provider's, not Hello's, so Hello is not the gate. The controller key lives in a **TPM key whose authorization value is `HKDF(GK, "tpm-auth")`**, supplied by the core after the gate releases `GK`. The TPM enforces the value and its own dictionary-attack lockout. While the identity is logged in the device-held copy of `GK` (section 2) lets the core reopen without the provider. Two alternatives are not taken: relying on the key-storage provider's user-interface policy (`NCRYPT_UI_POLICY`), which is a prompt and not the provider; and deriving an unwrap key from a deterministic Hello signature, which would put a second authenticator, released by Hello and not by the provider, back into the log-in path. A probe decides whether a non-interactive core process can drive the authorization value; if not, this section is revisited before anything is built for Windows.
- *If a macOS core process cannot reach the sealed blob that the signed app can,* the app releases `GK` and hands the core a derived unwrap token once per unlock, over the owner-proven local channel, and the core zeroes it. It is taken only if the first design fails, because it puts `GK` in the app's memory too. It adds no boundary a same-user process does not already have, since such a process can read the core's start secret.

### 4. What protects a locked identity while the provider is only a placeholder

**The app's own lock, and nothing beyond it.**

While the provider always answers 80, no secret exists that only the person has. No cryptography can honestly bind `GK` to a person, so this ADR does not pretend to. In that state:

- **Protected:** a profile's files copied off the device (the hardware layer, per profile); an identity that does not open on restart; a locked core that answers nothing but its lock state.
- **Not protected:** code running as the owner on the device can unwrap the gate copy of `GK` (its hardware key needs no person), ask the gate through the unlock route, and open the identity. The placeholder's answer is not evidence about a person. It clears the gate for everyone.

So that no screen or route overstates this, the lock reports a `lock_class`, derived and never inferred:

| `lock_class` | Meaning |
|---|---|
| `app_only` | the gate is satisfied by a placeholder provider |
| `secret_bound` | the owner set the optional identity secret below |
| `provider_bound` | a real provider's answer released `GK` |

**`provider_bound` is reported only after a real provider has released `GK`.** A build must not say, in a route, a screen or a log, that a locked identity is "protected by authentication" while the class is `app_only`. That is ADR-028's rule applied to a lock: the protection claimed is the protection that exists.

**An optional identity secret** (off by default) is the one owner-bound input available now. If set, `GK' = HKDF(GK, Argon2id(secret, salt))`, so the secret is a key input and not a check a copied file can skip. Wrong attempts are counted before any key-stretching work: five free, then delays doubling from one minute to one hour. The count is kept in the profile directory, so where the hardware layer is absent it slows a person down and does not stop an attacker with the files; the Security screen says so. Removing the secret needs the current one. Recovery is unaffected.

### 5. Locking, time and what is in progress

- **Default: no automatic lock after a period.** Log-out and switching are the lock. An optional inactivity timeout of 5, 15 or 60 minutes may be set.
- **When a lock fires** (log-out, switch, or the timeout): the core stops accepting requests; a request already running is given up to 30 seconds to finish; anything longer is cancelled and answered "identity is locked", and **never completed with a partial signature**. Secrets are then zeroed and the core stops.
- **Zeroing is best effort.** Go's runtime copies values and the operating system may page memory. The core overwrites the buffers it holds and locks memory where the platform allows. This reduces exposure; it is not a guarantee, and it is described that way wherever it is described. Ending the process is what ends the exposure.
- **A locked identity shows its name only** in the list of identities on the device: no picture and nothing else readable. That can be relaxed later.
- **Viewing the recovery phrase and exporting a backup** need the seed and so need a log-in. Nothing is cached to avoid it.
- **A paired controller asking a locked phone** fails with "identity is locked". A phone never unlocks because a peer asked. Prompting the person on the phone is not settled here.

### 6. Migration, and its point of no return

An existing profile is moved in steps: create the per-profile key and gate, seal the secret, read it back through the new path, then replace the envelope. A read-back that fails keeps the old envelope. An interrupted run resumes from the version the envelope records.

**The point of no return is deleting the old device-wide wrapping key.** It is deleted only after the last profile on the installation has moved and read back, and is a separate, last, logged step. Before it, going back to an earlier build costs nothing. After it, an earlier build cannot open a moved secret, and only the recovery phrase restores. No release is built that deletes the old key at the same time as it moves the first profile.

### 7. The profile's data is encrypted at rest under a key derived from `GK`

A logged-out identity whose data is still readable defeats the purpose of logging out: only its name may be readable. So encrypting a profile's data is part of this change, as its own phase after the keys.

**What is covered.** Everything the profile keeps that says something about its person:
- the SQLite identity store (`store/sqlite_store.go`): contacts, credentials, presentations, notifications, settings, the key event log, and every other table in it;
- the activity log (`activitylog`), which holds the activity trail;
- the conversation record and the delivery queue that an add-on keeps in the profile directory (ADR-068, ADR-069). Each is the add-on's, so the core gives the add-on the same key derivation through the add-on interface and refuses an add-on a database in the profile without it. The record keeps who said what, never the words, and it is still a trail.

Every SQLite database in the profile is opened through `sqlitedb.Open`, so that is the one place the key is applied: once a profile is gate-sealed, `Open` refuses a database without a key, so no store can be left out by being forgotten. Files that are not SQLite are written through a sealed-file writer beside `atomicfile`, under the same key.

**The key.** `dataKey(file) = HKDF(GK, "data-at-rest/v1/" + file name)`, one per file, so no two files share a key.

**The store.** The whole database file is encrypted page by page, including the write-ahead log and the journal, so the file on disk is ciphertext and its tables, sizes of rows and schema are not readable. `modernc.org/sqlite` has no such codec, so the driver changes. The candidates are an encrypting SQLite build with a page codec; the choice is a probe that must pass on all four platforms: it builds for iOS and Android through `gomobile` and for macOS and Windows, keeps WAL mode, and passes the existing store tests. Not taken: encrypting columns (leaves the schema, row counts and every index readable, and breaks queries); relying on the operating system's file encryption (it differs per platform and is not tied to `GK`); and leaving the data to the hardware layer (that protects the seed, not the rows).

**How the core opens it on log-in and closes it on log-out.**
- A **locked core opens no database at all.** It answers its lock-state route and the unlock route only, so it reads neither a seed nor any data.
- **On unlock**, the gate releases `GK`, the core derives each file's key, opens each store with it and then serves. A **logged-in profile reopened after a kill** reads the device-held copy of `GK` and does the same, with nobody present.
- **On lock** (log-out, switch or timeout, section 5): the core stops accepting requests, gives a running request up to 30 seconds, checkpoints and **closes every database handle**, zeroes the derived keys and `GK`, and stops. A store that cannot be closed is reported as not logged out, never as locked.
- Temporary files are kept in memory (`temp_store`), so no plaintext spills to disk.

**What it claims.** The same as `GK` (section 3): a copied profile directory of a locked identity yields ciphertext. Under `app_only` it does not stop same-user code on the unlocked device, which can unwrap `GK` and open the files. While the identity is logged in the files are open and readable by the core, and the operating system's page cache and swap may hold plaintext. Overwriting and deleting a plaintext original is best effort on flash storage and is described that way.

**Backup and recovery are unaffected in kind.** A backup is of an identity and not of an installation (ADR-039), so an archive is made from the open stores and carried under the backup's own protection; it is never a copy of the encrypted file. A restore writes through the open store. A device whose hardware key is lost loses its `GK` and so its encrypted data on that device, exactly as it loses its seed envelope; the way back is the recovery phrase and a backup.

**What stays readable while locked, and why.** The local owner proof, the `.pid` and `.port` files and the identity's card. The first three prove that this program started this core or identify a process, and hold nothing of the person; they cannot be encrypted under `GK` because the app needs them to stop a core that is locked. The card holds the name and nothing else that this ADR needs: the picture is not kept in it, and whether its identifier must be hidden is settled by the audit. The audit of each profile's remaining files and secure-storage items is done before building, and each one is either brought under `GK` or listed on the Security screen as readable while locked.

**What this section does not cover.** A conversation's words kept by a utility app (ADR-068, ADR-072) live in that app's own store on its own machine, which ADR-072 already encrypts; they are not files of this profile, and this section does not change them.

**Migration** (the point of no return is in section 6): for each plaintext database, write an encrypted copy, open that copy from cold and read it back (integrity check and row counts), and only then replace the original. The plaintext original, its WAL and its shared-memory file are overwritten and deleted after the encrypted copy has opened on a later start, as a separate, last, logged step. Before it, going back costs nothing. After it, the only way back is a backup. A read-back that fails keeps the plaintext original.

## Alternatives considered

- **Open with the operating system's face, fingerprint or passcode prompt.** Rejected. It proves a person is at the device, not that the provider scored them, and it would put a second authenticator into log-in. It also ties keys to the device's biometric enrolment, which this design does not do.
- **Fall back to the device's screen lock while no provider is configured.** Rejected. It would make the lock look stronger than the gate it stands in for, and it would need a "set up a screen lock" detour that a phone without one cannot take.
- **Keep the marker file and stop there.** Rejected. It is what is built today, and a deleted file opens the identity.
- **One gate key per device.** Rejected. A device may carry several people, and the gate for one must not open the others. Keying per profile costs nothing the envelope's version does not already cover.
- **Encrypt only the seed and the controller key.** Rejected. It leaves contacts, credentials and trails readable from a copied directory, so a logged-out identity would still be usable for what matters to its person (section 7).
- **Invalidate keys when a new fingerprint or face is enrolled.** Not adopted: the gate does not use the biometric. The recovery phrase remains the way back.

## Consequences

- **A locked identity cannot be opened by deleting a file or by copying its directory.** Every copy of `GK` on the device is sealed by a key that does not leave it, the device-held copy is deleted at log-out, and the gate releases `GK` only for a passing provider result. **That is the whole of what is claimed.** Under `app_only` any process running as the same user can call the unlock route, and the placeholder passes it, so the route requires the local owner proof, and that proof is readable by the same user. A same-user process can therefore open a locked identity today. The sealed copies of `GK` are readable by same-user code on Windows and macOS and by code inside the app on iOS and Android, for a locked identity as well as a logged-in one (section 3).
- **A real provider changes only the provider.** The gate, the envelope and the routes do not change; `lock_class` reaches `provider_bound` when one releases `GK`.
- **Today the lock is `app_only`.** An attacker with the user's own access to the unlocked device is not stopped by it. The ADR says so so that nothing else need.
- **A desktop cannot open without its root device, and a logged-out phone does not vouch.** That is intended: a person with only their Mac cannot open a locked identity, and a phone whose identity is logged out leaves its desktops locked until the person logs in on the phone.
- **A phone survives being killed because `GK` is on the device while logged in.** The price is the exposure above, and on Android a restart while the screen is locked reopens the identity only after the screen is unlocked.
- **Each platform needs a probe on real hardware** before its row in section 3 is a fact. A Secure Enclave, a Keystore with and without attestation, and a TPM cannot be exercised in a simulator or in tests.
- **A locked identity's data is ciphertext on disk** (section 7). It costs a change of SQLite driver, which is the largest single piece of work in this ADR, and a core that opens its stores on unlock instead of at start.
- **The device-wide wrapping key is eventually deleted** (section 6). That is irreversible without the phrase.

## What this does not settle

- **Splitting `GK`: one share on the device and one released by the person's root device on each log-in.** This is what would let a desktop not open without the phone and a phone not open without the provider's output, and so make the lock real before a real provider exists. It is hard to reverse once identities are sealed under it, so it is the open question of this ADR. Nothing may be built on `Gate` that assumes the answer.
- **A real authentication provider.**
- **Prompting a person on a locked phone when a controller asks.**
- **What an organisation's Identity Agent on a desktop does about holding a root.** ADR-006 says a desktop is a controller. An app that founds an identity on its own desktop core contradicts that. This ADR locks the controller key and does not design for that contradiction.
- **Wire formats**, with test vectors, for the unlock route and for the `ProviderResult` and `VouchedAuthentication` the gate checks. Each is set when it is built.

## What is built

**Built:**
- `authprovider.UntilHumanAuthenticationIsBuilt` and `PlaceholderScore` (80); `permission.DefaultMinimumScore` (80)
- the device-wide seed wrappers on iOS, macOS (build tag `sepblob`), Windows (never run) and Android (app-supplied host)
- the refusal to store a root seed unwrapped in a production build
- `VouchedAuthentication` for a desktop's score, signed by its root device
- a `locked` marker that an app writes on an explicit log-out
- the gate (`lockgate`: `Gate.Release`, `ProviderResult`), which releases only for a measured score of at least `permission.DefaultMinimumScore`, a fresh result used once, and (desktop) a voucher that verifies
- the two copies of `GK` (the gate copy and the device-held copy, deleted and proved deleted at log-out), each under the platform's wrapper, refused in a production build where there is none
- the gate layer of a stored seed and envelope version 2 (`secureenclave`, `GateSealer`), so a locked profile reads no seed, not even one stored before it had a gate
- the lock routes (`GET /api/lock/state`, `POST /api/lock/unlock`, `POST /api/lock/lock`, `PUT` and `DELETE /api/lock/secret`), closed to a controller, with the local owner proof required on each; a locked core answers only these and the owner-proof route
- locking drains a running request for up to 30 seconds, then cancels it and withholds its reply, so a signature the lock interrupted is never completed; a cancelled request's other side effects may still complete
- `lock_class` (`none`, `app_only`, `secret_bound`, and `gate_unreadable` for a gated profile whose record is missing or unreadable) and the statement a screen shows; `provider_bound` is named and cannot be reached yet. `secret_bound` is reported only while the recovery phrase and the backup key are held under `GK`; otherwise `app_only`
- a profile is gated when its stored seed is a version 2 envelope with a gate layer, even if its gate record is gone: it stays locked and is never taken for one made before locking existed
- the recovery phrases and the backup credential key sealed under `GK`, re-sealed with the seed when the identity secret changes
- a desktop core (macOS, Windows) is a controller by default and refuses an unlock with no voucher from its root device, which names this machine's controller identifier; only a Linux core (the black box, a development box) may be ungated when founded, decided from the platform first: a box identity file or an asked-for mode on a Mac, Windows, iOS or Android core is ignored and logged, a development build's `IDENTITY_AGENT_GATE_MODE` on a Mac or Windows computer accepts only `controller`, and a gated profile never becomes a phone; the public `GET /api/health` is answered while locked
- the optional identity secret, with the delay counted before any key-stretching
- a log-out whose deletion fails reports the identity as still open
- a hardware key per profile in each wrapper: the iOS keychain tag, the Android Keystore alias (the app registers a per-profile host beside the device-wide one; with none, every profile keeps the one key) and the Windows TPM key name, each made by `ProfileKeyName` and recorded in what it wrapped (the seed envelope's `key`, a held key's and a recovery phrase's `wrap_key`). macOS makes a key per wrap already. An envelope with no name opens under the device-wide key, which is not deleted
- a desktop's controller key under `GK`: the macOS key blob is sealed under it (a locked profile's blob on disk is ciphertext and the profile gets a signer that signs nothing, never the software signer), and the Windows TPM key is the profile's own with authorization value `HKDF(GK, "tpm-auth")`. **Written, not run:** the macOS enclave file compiles only on a Mac and the Windows TPM property names are unverified until the probe (section 3)

**Not built:**
- a root device that signs `IA-UNLOCK-VOUCHER-V1`: nothing outside the tests does yet. Until one does, a desktop (macOS, Windows) founded after this change cannot be reopened once it is logged out, because it cannot get a voucher. The signer is logged as later work
- a way back in for a development build's root on a Mac or Windows computer: a development build may found a root there (`FoundingPermitted` with `dev`), but the computer is gated as a controller and the root has no other root device to vouch for a log-in, so **such a root must not be logged out**: once logged out it cannot be unlocked. Only a development desktop organisation uses this; it is not a supported way to hold an identity
- the optional inactivity timeout (section 5)
- stopping the core on a lock: secrets are zeroed and the core refuses requests, but the process keeps running, and the relay, witnessing and add-ons keep running with whatever key material they cached, until the app ends the process (section 5 is not met until it does or the work is stopped)
- hiding all but the name of a locked identity in the list of identities (section 5): the recovery-phrase and backup-key files are sealed, but other files in a locked profile directory are readable until data at rest (section 7) is built
- the sealing of every other secret a profile holds under `GK`; only the seed, the recovery phrases and the backup key are
- the hijacked connections of a locked core are closed only if they were hijacked before the lock fired
- locking on a switch (the app's step)
- the migration of the seed envelopes and the removal of the device-wide key
- the audit
- the encrypting SQLite driver, the data keys, and opening and closing the stores on unlock and lock (section 7)
- the migration of each plaintext database (section 7)
- a real provider
- the probe for each platform in section 3, on a real device

## Wording this ADR makes untrue

When this is accepted, in the same change, these stop being true and are corrected:

- The comment in `seedwrap_ios.go` and the host contract for the Android key that the agent "runs without a person present, so the seed key has no user-authentication requirement". It stays true of the hardware layer and false of the secret, which the gate now holds.
- The statement, wherever it appears, that a seed is stored unwrapped on every platform but iOS (see `seedwrap.go`, corrected 2026-08-31, and ADR-028's note). A production build refuses to store one unwrapped. What is open is in section 3.
- Any statement that a Mac or Windows PC can hold an identity (ADR-006's "Computer only" on your own computer, withdrawn above).
- Any statement that a logged-out identity is "locked" meaning protected. The `locked` file is a hint for the app, not a protection.

The old wording may remain in ADR-028's history of how it was found.
