# ADR-069: A Delivery Queue Is Bounded and Expires, and It Is the Add-On's

**Status:** Proposed
**Date:** 2026-11-08
**Amended:** 2026-11-10 — the queue and its expiry are the add-on's, not the core's
**Deciders:** Rob Andersen
**Builds on:** ADR-068 (a conversation's trail keeps who said what, never the words)

---

## Decision

A sealed message held for a recipient that is briefly offline waits in a
**delivery queue**, and the queue is bounded and expires, whichever add-on keeps
it:

- **It is bounded.** The queue has a limit on messages and bytes, a share of
  each per conversation and per sender, and an age of seven days. At a bound a
  new message is refused; an accepted message is never dropped to make room.
- **It is kept across a restart.** A message is accepted only once it is saved,
  so one the sender was told was queued survives a restart.
- **It expires.** Every message held for the whole age is refused: the trail's
  entry for it is marked **not delivered**, the sealed copy is deleted, and the
  sender can be told. The entry is marked before the copy is deleted, so a
  failure between the two loses nothing; the next pass finishes it, and each
  entry is marked once.
- **It holds nothing it cannot mark.** The queue is taken with the trail it
  marks in, and it refuses a message for a conversation that trail does not
  keep. A message whose conversation no trail keeps is left held and logged,
  never deleted unmarked.

The queue's numbers are the same limits an app is held to elsewhere
(`limits.Limits`); a phone scales the capacity and not the age.

## Where it lives and what stays open

**Amended 2026-11-10.** Not every Identity Agent holds messages for an offline
recipient, so the queue and its expiry are not in the core. They belong to an
add-on kept outside this repository that holds messages for such a recipient,
together with its trail. The add-on
opens the queue in its data directory (`delivery-queue.json`), enforces the age
on its own tick, and marks the entry in its trail. An earlier version of this
ADR had the core keep one queue and expire it on the core's own tick, so that no
add-on could hold a message the core could not expire; that is withdrawn, and
the guarantee now rests on the queue itself, which an add-on is given no other
way to hold messages than by taking it with its trail.

What stays in the core is what another party needs: the limits that protect the
core (`limits.Limits`, `AppLimits`, the per-app request rate and its 429 with a
`Retry-After`, `RefuseAnAppOverItsRate`), the sliding window they count with
(`ratewindow`), and the plug-in point (`addon.Host`), which no longer carries a
queue. The format of a "not delivered" entry is the chain's own
(`agentmessage`, ADR-068), and `conversationbundle.Verify` checks it.

## Why

An age limit that an add-on enforces holds only as long as the add-on does, and
the way to make it hold is that the queue itself refuses what its trail does not
keep and expires what it holds. A sealed message cannot be read by whoever keeps
the queue, so the limit that matters is on how long it stays. Marking the entry
not delivered is a statement in the record about what happened, so it is made
by the part that keeps the record.

## Consequences

- A message undelivered after seven days is never silently lost: its entry says
  it was not delivered, and the sender is told.
- An Identity Agent built without the add-on runs no queue and no expiry, and
  has nothing to expire.
- Nothing is deleted without being marked first, and a message whose record is
  not unambiguously the trail's is kept, not dropped; the queue's own bounds
  still limit what such a message costs.
- Another add-on that wants a queue builds its own from the same limits; the
  core gives it none, and so no second queue shares this one's file.
