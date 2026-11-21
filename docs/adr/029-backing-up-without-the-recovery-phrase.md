# ADR-029: Backing Up Without the Recovery Phrase

**Status:** Accepted
**Date:** 2026-07-29
**Extends:** ADR-014 (Key Custody), ADR-027 (Hardware-Gated Signing Key Custody)
**Amended:** 2026-11-15 — a slot bound to the file it is in (see "Amendment, 2026-11-15: a slot bound to the file it is in" at the end)
**Amended:** 2026-11-15 — a key for each utility app, held in the core (see "Amendment, 2026-11-15: a key for each utility app, held in the core" at the end)

## Context

Every backup key slot derived its wrapping key from something the owner holds — the recovery phrase, a passphrase, a guardian group. That means the machine writing the archive had to be given one of those secrets. The client loaded the phrase and posted it with every export.

When that machine is one somebody else operates — an instance on a rented machine, a shared server, any hardware whose owner is not the identity's owner — handing it the phrase gives away the identity itself, permanently and irrevocably. Unpairing does not undo it; deleting the instance does not undo it. **A backup should not cost more than what it protects.**

It had two further consequences that were not obvious:

1. The phrase had to remain on the device forever, because a backup could not be taken without it.
2. Somebody who had dutifully written their phrase down and wanted it removed could no longer back up. The safe behaviour and the recommended behaviour were in opposition.

## Decision

Reverse the direction. The owner's device publishes a **public** key; the agent seals a randomly generated backup key to it and keeps nothing.

- A new key-slot type, `sealed_x25519_v1`, wraps the backup key to an X25519 public key using an ephemeral Diffie-Hellman exchange. The ephemeral private half is discarded immediately, so the machine cannot reopen its own archives.
- The sealing keypair is **derived from the same BIP39 seed the phrase produces**, at a domain-separated HKDF path. Recovery is therefore unchanged from the outside: somebody restoring types their words and never learns sealing was involved. A randomly generated sealing key would be one more thing to back up, and a backup key that must itself be backed up is not a solution.
- It is deliberately **not** the identity's signing key. Reusing a signing key for encryption weakens both, and rotating the identity would silently break every existing archive.
- The archive **names no recipient**. An identity with several owners gets one slot each, and opening it means trying them in turn. Naming them would publish who owns an identity to anyone holding a copy of its backup — the wrong place for that to leak. A slot meant for somebody else fails its authentication tag rather than yielding anything, so trying costs nothing.
- **Any single owner can restore the data.** They are already entitled to it, and requiring several people to assemble before anyone can read a backup only adds a way to lose it. Acting *as* a multi-owner identity is a different question, answered by the signing threshold.

The recovery public key is delivered **with the delegation, during pairing**, rather than configured afterwards. The gap between those two is the one window where a device is running, holding real data, and unable to protect any of it.

Correspondingly, the client no longer sends the phrase at all. A delegated device seals to the keys it was given; a root device reads its own wrapped seed from disk. Both derive the same key the phrase would have derived.

Two related changes follow from the same reasoning:

- **`AND` slot policy is now enforced.** The format could declare it and nothing honoured it, so adding a passphrase made an archive *easier* to open — a second independent door. Under `AND` the slots hold an intermediate secret and the payload key is wrapped again by that secret combined with the passphrase; the passphrase gets no slot of its own, since a slot would be the exact bypass the policy exists to prevent.
- **The recovery words are deleted once their owner confirms they are recorded.** The words and the seed are different things kept for different lengths of time: the seed stays, because every future pairwise contact key, login relationship, asset key and the credential vault derives from it. The words are only an encoding of it.

## Consequences

**Good.** A machine the identity's owner does not control can back up an identity it cannot read. The phrase stops being the price of a routine operation, which is what makes deleting it after recording possible. For an organisation, one slot per signer is the same mechanism with no wire change.

**Costly.** An agent that has neither a seed nor recovery keys must refuse to export rather than write an archive nobody could open — a new failure mode, and the right one. Pairing gained a required field.

**Accepted risk.** Trial decryption across slots is O(recipients). With a handful of owners this is negligible; an identity with hundreds of signers would want an index, at the cost of the privacy property above.

## Alternatives Considered

**Split the backup key across owners with Shamir sharing.** Rejected. It makes reading the data require a quorum, and losing data is worse than an owner reading what they are already entitled to read. Data availability should be forgiving; authority should not.

**Name recipients in the manifest so the right slot can be found directly.** Rejected: the manifest is not encrypted, so it would publish an organisation's ownership to anyone holding its backup.

**Keep sending the phrase and accept it.** Rejected. It is the thing that makes running on hardware you do not control unsafe, and it forced the phrase to live on the device permanently.

## Amendment, 2026-11-15: a slot bound to the file it is in

### Context

A `sealed_x25519_v1` slot wraps the backup key with no authenticated data. That is right while a file's body is authenticated against its whole header, slots included, but then no slot can ever be added to a file, because adding one changes the header and the body no longer opens. A holder of the backup key who is asked to give the file to a new recipient would have to re-encrypt the body.

### Decision

A second slot type, `sealed_x25519_v2`, for a backup whose body authenticates only a fixed preamble and a random 16-byte **file identifier**, not its slots.

- The slot layout is unchanged: ephemeral public key (32 bytes), nonce (12), wrapped backup key with its tag (48).
- The key that wraps the backup key comes from the same X25519 exchange and the same HKDF-SHA256 (salt: the ephemeral public key then the recipient's public key), under its own label, `identity-agent-backup-seal-shared-v2`, in place of `identity-agent-backup-seal-shared-v1`.
- The wrap is AES-256-GCM with the **file identifier as its authenticated data**.

So a slot lifted out of one file does not open in another, a v1 slot is never read as a v2 slot or the other way round, and whoever holds a file's backup key can add a slot for a new recipient without touching the body. The archive still names no recipient (the rule above is unchanged), and any single recipient's slot still opens it.

`UnsealBEKForFile` opens such a slot. The committed vectors for both slot types are in `identity-agent-core/backup/testdata/seal-slot-vectors.json`; an implementation that writes these slots checks its output against them. `SealSlotForFile` writes one, for the per-utility-app keys below.

### Consequences

A file format that uses v2 slots must authenticate its body against the preamble and the file identifier, never the slots, and must draw a fresh random backup key for every file (a holder who is asked to open a file hands back that file's key). Removing a slot only denies access to that recipient; it does not change the key, so a recipient who already holds the key keeps it.

## Amendment, 2026-11-15: a key for each utility app, held in the core

### Context

A utility app that makes backups seals them to a public key and cannot read them back. That key is the Identity Agent's own, and an add-on (a program that runs inside the Identity Agent) shows it to the owner and opens a backup when the owner approves. Deriving the key takes the identity's root seed, from which the identity's signing keys, its pre-rotated next keys and every asset's keys also come. An add-on that held it would put all of them within reach of a bug in the add-on.

### Decision

- **One key per utility app and epoch.** The private key is HKDF-SHA256 over the root seed (salt `identity-agent-backup-seal-salt-v1`), with the label `identity-agent-backup-seal-app-v1`, then the utility app's identifier (its qb64 identifier as ASCII bytes, never a display name) preceded by its length in two bytes, big endian, then the epoch (starting at 1) in four bytes big endian. It is never a person's key (`identity-agent-backup-seal-v1`). One leaked key opens one utility app's files at one epoch. It works for any Identity Agent that holds a root seed of its own identity.
- **The core holds it.** An add-on is given the public key (`BackupSealKeyOf`), which of a file's slots opens (`BackupSlotOpens`), a slot for another utility app's key at an epoch (`ResealBackupSlot`: the caller names the app and the epoch, and the core derives the destination key, so a content key only goes to a key the core holds), and the content key sealed to a restore key (`SealBackupOpenReply`, which refuses a restore key the core itself holds). It is never given the seed, a private key or the content key. `IsOwnBackupSealKey` tells it whether a key is one the Identity Agent itself opens backups with. Epochs are capped at 1024 and a file at 255 slots.
- **Fails closed.** With no root seed of the identity's own, or where the identity's signing key is not the one that seed derives, there is no key; asking for one creates no seed.
- **The reply.** The content key sealed to the restore key: ephemeral public key (32), nonce (12), wrapped key with its tag (48). The wrapping key is HKDF-SHA256 of the X25519 result (salt: the ephemeral public key then the restore key, label `identity-agent-backup-open-reply-v1`), and the wrap is AES-256-GCM with the 32-byte digest of the request as authenticated data, so a reply is for one request and never opens as a slot of either kind.

The committed vectors are in `identity-agent-core/backup/testdata/seal-app-vectors.json`.

### Consequences

The core protects the seed and the content key; it does not decide who receives a content key it is asked to seal to a restore key. That decision, the owner's consent, is the add-on's.

Anyone who holds the root seed, including a signer removed since, can derive every utility app's key offline; the Identity Agent's own archive is sealed to its signers. Keeping the seed in the core removes the online route to it from add-on code, not that one.
