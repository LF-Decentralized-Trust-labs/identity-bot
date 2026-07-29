# ADR-029: Backing Up Without the Recovery Phrase

**Status:** Accepted
**Date:** 2026-07-29
**Extends:** ADR-014 (Key Custody), ADR-027 (Hardware-Gated Signing Key Custody)

## Context

Every backup key slot derived its wrapping key from something the owner holds — the recovery phrase, a passphrase, a guardian group. That means the machine writing the archive had to be given one of those secrets. The client loaded the phrase and posted it with every export.

When that machine is a rented computer in somebody else's building, handing it the phrase gives away the identity itself, permanently and irrevocably. Unpairing does not undo it; deleting the instance does not undo it. **A backup should not cost more than what it protects.**

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

**Good.** A rented machine can back up an identity it cannot read. The phrase stops being the price of a routine operation, which is what makes deleting it after recording possible. For an organisation, one slot per signer is the same mechanism with no wire change.

**Costly.** An agent that has neither a seed nor recovery keys must refuse to export rather than write an archive nobody could open — a new failure mode, and the right one. Pairing gained a required field.

**Accepted risk.** Trial decryption across slots is O(recipients). With a handful of owners this is negligible; an identity with hundreds of signers would want an index, at the cost of the privacy property above.

## Alternatives Considered

**Split the backup key across owners with Shamir sharing.** Rejected. It makes reading the data require a quorum, and losing data is worse than an owner reading what they are already entitled to read. Data availability should be forgiving; authority should not.

**Name recipients in the manifest so the right slot can be found directly.** Rejected: the manifest is not encrypted, so it would publish an organisation's ownership to anyone holding its backup.

**Keep sending the phrase and accept it.** Rejected. It is the thing that makes renting hardware unsafe, and it forced the phrase to live on the device permanently.
