# ADR-039 — A backup is of an identity, not of an installation

**Status:** Accepted
**Date:** 2026-09-04
**Extends:** ADR-029 (Backing Up Without the Recovery Phrase)
**Relates to:** ADR-006 (Standardized Topology), ADR-027 (Hardware-Gated Signing Key Custody)

## Context

ADR-029 settled how an archive is sealed and who can open it. It never said what a
backup is *of*. The gap was not visible while every installation held an identity,
because then the two answers coincide.

They stopped coinciding once an Identity Agent could act **for** an identity instead
of holding one — running the interface, holding its own hardware key, granted
authority by the identity's owner, while the identity itself lives elsewhere. An
installation may also hold sealed archives on another identity's behalf, or exist
only for the length of a recovery. In none of those cases is the installation the
thing worth preserving, and treating it as one produces a concrete failure:

> A machine is authorised to act, then revoked. Restoring an archive taken before
> the revocation authorises it again, with nothing having said so.

That is not a bug in the revocation path. It is what follows from restoring the
wrong unit.

## Decision

**Backup and recovery apply to identities, never to installations.**

What is backed up is an identity and every part of it:

- Where an identity is split across paired devices — one holding the keys, another
  holding the data and always-on services — **both are backed up, as one identity.**
- Where an identity lives wholly on one computer, including a black box computer,
  **that computer's identity data is backed up, as one thing.**

What is never backed up:

- **An installation acting for an identity rather than holding one.** It holds no
  identity, no derived seed and no personal data — only its own hardware key and
  its own record of which identity it serves. The hardware key cannot be carried to
  another machine by construction (ADR-027); that non-extractability is the entire
  property it exists for, so restoring it elsewhere is not possible and would
  defeat the purpose if it were. Such an installation returns by being paired and
  granted authority again.
- **An installation holding archives on another identity's behalf.** Those archives
  are copies of an identity that still exists. Losing the installation costs a copy,
  not the identity; the answer is to appoint another holder, never to restore the
  one that was lost.
- **An installation performing a recovery.** It exists for the length of the
  operation and has nothing of its own to preserve.

### This follows from the design rather than constraining it

An Identity Agent already refuses to act for another identity while it holds one of
its own — `beAFrontEndFor` in `server/this_core_is_only_a_front_end.go` rejects the
request when an identity is present, because silently becoming the second would
leave a real identity unreachable through the software that holds it.

So an installation either **holds** an identity or **acts for** one, never both.
"Back up identities" and "do not back up installations that act for them" are one
sentence, not two rules that could disagree.

### What a controller may keep

An installation acting for an identity may hold local conveniences — which identity
was last shown, window layout, and similar. It may **never** hold anything whose
loss would matter.

This is the test for anything proposed later: if something such an installation
holds would be missed after it is gone, that is the signal the thing belongs on the
identity's side. It is never a reason to start backing up installations.

## Consequences

**Which machines may act is never carried in an archive.** `skipReason` in
`backup/everything_this_device_holds.go` excludes the record of granted
controllers, so no archive holds one to restore.

What follows differs by where the archive lands, and the difference is worth
stating because only one half is a cost:

- Onto a **fresh installation** there are no controllers, and each machine must be
  granted again. That is the right cost — after a restore, which machines may act
  is exactly the question an owner should be asked rather than have answered from
  a file.
- Onto an installation that **already holds grants**, a restore leaves them
  untouched, because a restore writes the sections an archive names and deletes
  nothing. Those grants are the current ones rather than a resurrected past, which
  is the correct outcome and the reason nothing has to reconcile them.

**Revocation stays complete.** A grant is consulted only by the Identity Agent
holding it; there is no published list and no other party to inform. The restore
path was the one place a revocation could leak, and it is closed at the source
rather than reconciled afterwards.

**A machine that finds itself no longer authorised is an ordinary state**, not a
fault, and it can arise without any restore — through revocation, or because the
identity it served moved. It is not evidence that something was lost.

**An absent grant record is an ordinary first-run state.** Nothing may treat its
absence as an error, since that is now the normal condition of every restored
Identity Agent.
