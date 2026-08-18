# The `.iab` backup archive format

A single-file, envelope-encrypted archive of an Identity Agent's state, written as `magic | manifest length | cleartext JSON manifest | AES-256-GCM ciphertext`.

This document is derived from the Go implementation in `identity-agent-core/backup/` and
`identity-agent-core/recovery/`, which is the normative source. Where the code and the
JSON schema at `identity-agent-core/contracts/backup-format/iab-format.schema.json`
disagree, the code wins and the disagreement is listed in "Schema drift" below.

## 1. What the format is for

A `.iab` file carries everything an Identity Agent needs to be rebuilt on another machine —
identity state, the key event log, the root keystore seed, contacts, credentials and
settings — encrypted so that the machine holding the file cannot read it. It is designed so
that the machine *writing* the archive need not hold any secret that opens it, which lets an
agent running on hardware its owner does not control take backups it can never read back.

## 2. File structure

An archive is one flat byte sequence. There is no container, no compression and no trailer.

| Offset | Length | Content |
|---|---|---|
| 0 | 4 | Magic, the ASCII bytes `IAB1` |
| 4 | 4 | Manifest length, unsigned 32-bit, big-endian |
| 8 | *manifest length* | Manifest, UTF-8 JSON, cleartext |
| 8 + *manifest length* | to end of file | Ciphertext |

Written by `EncodeArchive` and read by `DecodeArchive` in `backup/format.go`.

The magic string is a constant (`IABMagic = "IAB1"`) and is not parsed for a version — the
version lives in the manifest, in `format_version`, whose current value is `1`
(`FormatVersion` in `backup/format.go`).

`DecodeArchive` rejects a file shorter than 8 bytes, a file whose first four bytes are not
`IAB1`, and a file whose declared manifest length runs past the end of the file. Everything
after the manifest is taken as ciphertext; a zero-length ciphertext is not rejected at this
stage.

**The ciphertext** is AES-256-GCM over the serialised payload bundle, using a 12-byte nonce
recorded in the manifest as `payload_nonce_b64`. The GCM authentication tag is appended by
the Go standard library and is therefore part of the ciphertext bytes. No additional
authenticated data is passed (`gcm.Seal(nil, nonce, plaintext, nil)` in
`EncryptPayload`, `backup/crypto.go`), so the manifest is **not** covered by the payload's
authentication tag. See "What is and is not tamper-evident" in section 7.

**The plaintext** inside the ciphertext is a JSON *array* of section objects — not an object
with a `sections` key. `SerializePayloadBundle` marshals `bundle.Ordered` directly. Each
element is:

```json
{ "name": "identity_state", "data": "<standard base64 of the raw section bytes>" }
```

`data` is a Go `[]byte`, so `encoding/json` renders it as padded standard base64.

**File naming.** The format does not define a filename. When the agent writes to a local
destination it uses `backup-<snapshot type>-<UTC YYYYMMDD-HHMMSS>.iab`
(`backup/service.go`), and when a backup-only device receives an archive it stores it as
`<UTC YYYYMMDD-HHMMSS>.iab`. Both are conventions of that code path, not of the format.

## 3. The manifest

The manifest is cleartext JSON. It is the `Manifest` struct in `backup/format.go`.

| Field | Type | Meaning and use |
|---|---|---|
| `format_version` | integer | Format version of this file. Always written as `1`. A reader refuses anything greater than the version it knows. |
| `created_at` | string | RFC 3339 UTC timestamp of archive creation. Informational; nothing reads it back. |
| `identity_aid` | string, optional | The AID of the identity this archive belongs to. A label only — omitted when the store has no identity. Recovery uses it to report which identity an archive claims to be, and prefers the AID inside the decrypted `identity_state` when both are present (`recovery/service.go`). |
| `tiers` | array of string | Which tiers were requested: `tier1`, `tier2`, `tier3`. Defaults to `["tier1"]`. Informational on read; nothing validates it against the sections actually present. |
| `snapshot_type` | string | `full` or `delta`. Records whether this archive holds everything collected or only tier 1 plus changed tier 2/3 sections. Nothing on the read path treats a delta differently — see section 7. |
| `sections` | array | One entry per section in the payload, in payload order. Each has `name`, `digest_blake3_qb64` and `size_plaintext`. This is what makes the payload integrity-checkable. |
| `key_slots` | array | The wrapped copies of the content key. See section 4. |
| `slot_policy` | string | `or` or `and`. The archive-level rule for how many factors are needed. This is the value the reader consults. |
| `argon2_params` | object, optional | Present only when a passphrase slot exists. `memory_kib`, `iterations`, `parallelism`, `salt_len` — the Argon2id parameters the reader must reuse to reproduce the passphrase key. |
| `delta_state_digest_blake3_qb64` | string, optional | The delta chain digest as of this archive, so a chain can be checked for continuity. Written but never read — see "Not implemented". |
| `external_pointers` | array, optional | Bulk data deliberately left outside the archive: `domain`, `locator`, `key_ref`, optional `size_bytes` and `archived_at`. Written but never read — see "Not implemented". |
| `payload_nonce_b64` | string | The 12-byte AES-GCM nonce for the payload, standard base64. |
| `and_wrapped_bek_b64` | string, optional | Second-layer wrapped content key. Present only under `and`. |
| `and_nonce_b64` | string, optional | Nonce for the second layer. Present only under `and`. |

Section entries:

| Field | Meaning |
|---|---|
| `name` | Section name, matched positionally against the payload. |
| `digest_blake3_qb64` | Blake3-256 of the section's plaintext bytes, CESR-style qb64 with the `E` derivation code (`iacrypto.Blake3QB64`). |
| `size_plaintext` | Byte length of the section's plaintext. Written, never checked on read. |

All base64 in the manifest is standard alphabet **with** padding — `EncodeB64` /
`DecodeB64` use `base64.StdEncoding`. (The comment on `EncodeB64` in `backup/crypto.go`
says "without padding", which does not match the code.)

## 4. The key slot model

A slot is one wrapped copy of a secret. Four slot types are defined in `backup/format.go`:

| `type` | Unlocked by | Written by the exporter? |
|---|---|---|
| `seed_hd_v1` | The BIP39 seed, from the 24-word recovery phrase or supplied directly. | Yes, whenever the caller supplies a mnemonic or seed. |
| `passphrase_argon2id_v1` | A user passphrase, stretched with Argon2id using the salt on the slot and the parameters in the manifest. | Yes, whenever a passphrase is supplied. |
| `sealed_x25519_v1` | An X25519 private key the writing machine never held. | Yes, one slot per configured recovery public key. |
| `guardian_multisig_v1` | Nothing in this codebase. | No — see "Not implemented". |

Every slot carries `wrapped_bek_b64` and `nonce_b64`, except the passphrase slot under
`and`, which carries only `argon2_salt_b64`.

Each slot also carries a `policy` field, set to the archive's policy when the exporter
writes it. The reader ignores the per-slot field and uses the manifest's `slot_policy`.

### `seed_hd_v1`

The key-encryption key is
`HKDF-SHA256(ikm = BIP39 seed, salt = "identity-agent-backup-salt-v1", info = "identity-agent-backup-kek-v1")`,
32 bytes (`DeriveBackupKEK`). The slot holds the secret wrapped under that key with
AES-256-GCM.

The BIP39 seed itself is `PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048
iterations, 64 bytes)`. The mnemonic must be **exactly 24 words**; any other count is
rejected. Internal callers always pass an empty BIP39 passphrase.

### `passphrase_argon2id_v1`

A 16-byte random salt is generated per archive and stored on the slot. The key is
`Argon2id(passphrase, salt, iterations, memory_kib, parallelism, 32 bytes)` using the
parameters written into `argon2_params`. Defaults: 65536 KiB memory, 3 iterations,
parallelism 4, salt length 16 (`DefaultArgon2Params`). `DerivePassphraseKEK` requires a salt
of at least 8 bytes and does not otherwise consult `salt_len`.

### `sealed_x25519_v1`

Lets a machine write an archive it cannot read. Per recipient:

1. A random 32-byte ephemeral scalar is generated; its public half is
   `X25519(ephemeral, basepoint)` and is stored on the slot as `ephemeral_pub_b64`.
2. The shared secret is `X25519(ephemeral, recipient public key)`.
3. The wrapping key is
   `HKDF-SHA256(ikm = shared secret, salt = ephemeral public || recipient public, info = "identity-agent-backup-seal-shared-v1")`,
   32 bytes.
4. The secret is wrapped under that key with AES-256-GCM. The ephemeral private half is
   discarded.

The recipient keypair is derived from the same BIP39 seed the recovery phrase produces:
`HKDF-SHA256(ikm = BIP39 seed, salt = "identity-agent-backup-seal-salt-v1", info = "identity-agent-backup-seal-v1")`
gives the 32-byte private half, and the public half is `X25519(private, basepoint)`
(`DeriveSealKeypair`, `backup/crypto_seal.go`). So somebody restoring from the phrase alone
opens a sealed archive without supplying anything extra.

**No slot names its recipient.** There is deliberately no recipient field. A reader tries
each sealed slot in turn; a slot meant for a different recipient fails its GCM
authentication tag rather than yielding anything. The reasoning is recorded in
`docs/adr/029-backing-up-without-the-recovery-phrase.md`.

### What `slot_policy` means

**`or`** — any single slot opens the archive. Every slot wraps the content encryption key
itself. Adding a passphrase under `or` therefore makes an archive *easier* to open, not
harder: it adds a second independent door.

**`and`** — a slot is necessary but not sufficient. The slots do not hold the content key at
all. They hold an intermediate 32-byte random secret. The content key is wrapped a second
time under
`HKDF-SHA256(ikm = intermediate secret, salt = Argon2id passphrase key, info = "identity-agent-backup-and-combine-v1")`
(`CombineFactors`), and that second wrap is stored in the manifest as `and_wrapped_bek_b64`
and `and_nonce_b64`. Opening a slot gets you the intermediate secret and no further.

Consequences of `and`, all enforced in code:

- Export fails if no passphrase is supplied (`backup/archive.go`).
- The passphrase gets **no unlockable slot**. A passphrase slot is still written, carrying
  only `argon2_salt_b64` and `policy: "and"`, because the salt must travel; it wraps
  nothing. A reader skips passphrase slots entirely when the policy is `and`.
- Reading fails immediately if no passphrase is supplied.

The default when the caller does not specify is `or` (`NewManifest`).

## 5. How the content encryption key is generated and wrapped

The content encryption key (called the BEK, backup encryption key, in the code) is 32 random
bytes from `crypto/rand` (`NewBEK`). It is generated fresh for every archive and is never
derived from anything.

The payload is encrypted with AES-256-GCM under that key, with a fresh 12-byte random nonce
recorded in the manifest.

Under `or`, each slot wraps the content key directly: AES-256-GCM with a fresh 12-byte nonce
per slot, under that slot's key-encryption key. `UnwrapBEK` rejects a result that is not
exactly 32 bytes.

Under `and`, a second 32-byte random secret is generated. Slots wrap *that*; the content key
is wrapped under the combination of that secret and the passphrase key, and stored in the
manifest.

An export with no mnemonic, no seed and no recipient public keys is refused outright, rather
than producing an archive nobody can open.

## 6. Sections a collector writes

Sections come from `Collector.Collect` in `backup/collector.go`. Requesting `tier2` or
`tier3` implies the tiers below it.

**Tier 1 — always included when any tier is requested**

| Section | Contents |
|---|---|
| `identity_state` | The store's identity record, as JSON. Omitted when there is no identity. |
| `kel_events` | The key event log for the identity's AID, as a JSON array. Written even when empty. |
| `sqlite_identity_db` | Raw bytes of `identity.db`, only when the store is the SQLite store and the file reads successfully. |
| `login_relationships` | Raw bytes of `login_relationships.json`, when present. |
| `root_seed` | The raw root keystore seed, **unwrapped**. Every HD-derived key — pairwise contact keys, login relationships, the credential vault key — re-derives from it, so a restore onto new hardware must not depend on the old device's secure element. Present only when `secureenclave.LoadRootSeed` succeeds. |

**Tier 2**

| Section | Contents |
|---|---|
| `contacts` | All contact records, as JSON. |
| `credentials` | All credential records, as JSON. |
| `settings` | Settings, as JSON. |
| `pending_requests` | Pending requests, as JSON. |

**Tier 3**

| Section | Contents |
|---|---|
| `sandbox_index` | A JSON object `{"entries": [<file names in the sandbox directory>]}`. Names only — no container images and no app data. |
| `ai_memory_db` | Raw bytes of `ai_memory.db`. Written **only** when `LeanTier3` is false. In lean mode (the default) it becomes an external pointer instead. |
| `log_<basename>` | Raw bytes of one log file newer than the retention window (default 30 days). Written **only** when `LeanTier3` is false. |

Tier 3 in the default lean mode emits `external_pointers` rather than bytes: one for
`ai_memory.db`, and one for each log file older than the window. Each pointer records
`domain`, a `locator` that is a **local filesystem path**, a `key_ref`, `size_bytes` and
`archived_at`. Nothing in the archive makes that data retrievable from another machine.

**Delta archives.** When the snapshot type is `delta`, `FilterDeltaBundle` in
`backup/delta.go` keeps the four names in `tier1SectionNames` — `identity_state`,
`kel_events`, `sqlite_identity_db`, `login_relationships` — unconditionally, and keeps a
tier 2/3 section only when its Blake3 digest differs from the previous recorded digest.
`root_seed` is in neither list, so it is dropped from every delta archive; see "Not
implemented".

## 7. Reading an archive back

`OpenArchive` in `backup/archive.go`, in order:

1. Decode the framing: length, magic, manifest bounds, manifest JSON.
2. Reject `format_version` greater than the reader's own version.
3. Decode `payload_nonce_b64`.
4. Resolve the BIP39 seed from the supplied seed bytes, or from a supplied 24-word mnemonic.
5. If `slot_policy` is `and` and no passphrase was supplied, fail before trying anything.
6. Derive the sealing private key from the seed, unless the caller passed one directly.
7. Walk `key_slots` in manifest order and try each one by type. The first slot that yields a
   secret wins. A sealed slot is skipped when there is no sealing key; a seed slot when
   there is no seed; a passphrase slot when there is no passphrase, no `argon2_params`, or
   the policy is `and`. Any other type is skipped. If nothing opens, the error is
   "no key slot unlocked", carrying the last unwrap error if there was one.
8. Under `and`, combine the recovered intermediate secret with the Argon2id passphrase key
   — using the salt from the first passphrase slot that carries one — and unwrap
   `and_wrapped_bek_b64` to get the real content key.
9. Decrypt the payload with AES-256-GCM. A wrong key or altered ciphertext fails here.
10. Parse the payload as a JSON array of sections.
11. `ValidateSections` checks, in this order: the number of manifest sections equals the
    number of payload sections; each name matches positionally; each payload section's
    recomputed Blake3-256 qb64 digest equals the manifest digest. Any mismatch is reported
    as "integrity check failed".

Above that, `recovery/restore.go` parses `identity_state`, `kel_events` and `contacts` out of
the decrypted bundle, and `recovery/service.go` re-derives each contact's HD pairwise public
key from the seed and compares it against the value stored in the contact record, reporting a
mismatch per contact.

On activation, `recovery/service.go` writes back: the identity record, every KEL event, every
contact, `login_relationships.json`, the root seed (re-wrapped under *this* device's
hardware key where available) and `identity.db`.

**What is and is not tamper-evident.** The payload's GCM tag covers the payload only. Section
content cannot be altered without failing decryption, and sections cannot be added, removed
or reordered without failing `ValidateSections`. But no tag covers the manifest, so
`created_at`, `identity_aid`, `tiers`, `snapshot_type`, `delta_state_digest_blake3_qb64` and
`external_pointers` can be altered by anyone holding the file, and nothing detects it.
`size_plaintext` is likewise never verified.

**Delta archives are not reassembled.** `OpenArchive` does not know or care that
`snapshot_type` is `delta`. Opening a delta archive yields exactly the sections it contains.
Nothing in the codebase merges a delta onto a preceding full archive.

## 8. Version and compatibility

- The writer always writes `format_version: 1`.
- A reader **must refuse** an archive whose `format_version` is greater than the version it
  implements. The current reader returns `unsupported format_version <n>`.
- There is no lower bound. A missing or zero `format_version` is accepted, because the field
  decodes to `0` and only the greater-than test is applied.
- Unknown manifest fields are ignored — the manifest is decoded with Go's `encoding/json`
  into a fixed struct.
- An **unknown slot type is skipped silently** and the reader continues to the next slot. If
  no known slot opens the archive, the failure is the generic "no key slot unlocked". A
  reader therefore degrades to "I cannot open this" rather than erroring on the unknown type
  — which also means an archive written with only future slot types is indistinguishable
  from one written with the wrong keys.
- There is no minimum-reader-version field, no capability list and no negotiation.

## Schema drift: the JSON schema is stale

`identity-agent-core/contracts/backup-format/iab-format.schema.json` does not describe what
the code writes. Nothing in the repository validates against it — no code, test or script
references the file. Known divergences:

| Point | Schema says | Code does |
|---|---|---|
| Slot type enum | `["seed_hd_v1", "passphrase_argon2id_v1", "guardian_multisig_v1"]` (line 36) | Also defines and writes `sealed_x25519_v1` (`backup/format.go:34`, written at `backup/archive.go:162-168`) |
| Required slot fields | `wrapped_bek_b64` and `nonce_b64` required on every slot (line 34) | The passphrase slot under `and` has neither, only `argon2_salt_b64` (`backup/archive.go:203-207`) |
| `ephemeral_pub_b64` | Not present | Written on every sealed slot (`backup/format.go:83`) |
| `and_wrapped_bek_b64`, `and_nonce_b64` | Not present | Manifest fields written under `and` (`backup/format.go:115-116`) |
| Description | Refers to an internal work-item identifier (line 5) | No such reference exists in the code |

The schema is otherwise consistent with the code: the field names, the `or`/`and` policy
enum, the tier enum, the `E`-prefixed digest pattern and the required top-level fields all
match.

## Not implemented

Things the format defines or records but that no code path completes.

- **`guardian_multisig_v1` is never written and could not be read.** The type is defined at
  `backup/format.go:31`. The only way to get one into an archive is
  `ExportRequest.GuardianSlots` (`backup/archive.go:15`), appended verbatim at
  `backup/archive.go:223`; no caller in the repository ever sets that field. Even if one
  were present, `OpenArchive`'s type switch has no case for it, so it falls to the `default:
  continue` at `backup/archive.go:346` and is skipped.
- **`delta_state_digest_blake3_qb64` is write-only.** Set at `backup/archive.go:79` from
  `backup/service.go:200`. No read path anywhere consults it; the delta chain is verified
  from local state in `backup/config.go` storage, not from the archive.
- **`external_pointers` is write-only.** Set at `backup/archive.go:78`. Nothing in
  `recovery/` reads it. The `locator` values are local absolute paths
  (`backup/collector.go:174`, `:205`), so the data they name is unreachable from a restore on
  a different machine.
- **`size_plaintext` is never verified.** Written at `backup/archive.go:89`;
  `ValidateSections` (`backup/format.go:156-173`) checks count, order and digest only.
- **`root_seed` is dropped from delta archives.** The collector writes it at
  `backup/collector.go:119`, but it is absent from `tier1SectionNames`
  (`backup/delta.go:25-30`) and from `isTier2Or3Section` (`backup/delta.go:32-43`), so
  `FilterDeltaBundle` (`backup/delta.go:160-172`) excludes it from every delta archive. A
  restore from a delta archive alone reseats no root seed
  (`recovery/service.go:327`).
- **Tier 2 and tier 3 sections are collected but not restored.** `applyPayload`
  (`recovery/service.go:294-339`) writes back identity, KEL events, contacts,
  `login_relationships`, `root_seed` and `sqlite_identity_db`. `credentials`, `settings`,
  `pending_requests`, `sandbox_index`, `ai_memory_db` and `log_*` are decrypted and
  integrity-checked but never applied.
- **`DeltaStateHMAC` is dead code.** Defined at `backup/crypto.go:250`, called from nowhere.
  Its own comment describes it as a placeholder.
- **`tiers` is not enforced.** Written from the request; no reader compares it against the
  sections actually present.
- **`EncodeB64`'s comment contradicts its behaviour.** `backup/crypto.go:256` says "standard
  base64 without padding"; the code uses `base64.StdEncoding`, which pads.

## Not determined from code

- Whether any non-Go implementation of this format exists, and whether the manifest is
  expected to be canonically ordered for cross-implementation byte equality. Go's
  `encoding/json` emits struct fields in declaration order; nothing states this is normative.
- Whether `format_version` is intended to gate the framing, the manifest schema, the crypto
  suite, or all three. Only the single greater-than comparison exists.
- The intended retrieval mechanism for `external_pointers` — `key_ref` values are written as
  `local:<filename>`, and no consumer of that string exists.
