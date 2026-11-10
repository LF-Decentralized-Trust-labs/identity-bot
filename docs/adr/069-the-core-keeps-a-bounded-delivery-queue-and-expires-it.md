# ADR-069: The Core Keeps a Bounded Delivery Queue and Expires It

**Status:** Proposed
**Date:** 2026-11-08
**Deciders:** Rob Andersen
**Builds on:** ADR-068 (a conversation's trail keeps who said what, never the words)

---

## Decision

The Identity Agent's core keeps one delivery queue for sealed messages held for
a recipient that is briefly offline, and the core, not an add-on, enforces its
limits:

- **It is bounded.** The queue has a limit on messages and bytes, a share of
  each per conversation and per sender, and an age of seven days. At a bound a
  new message is refused; an accepted message is never dropped to make room.
- **It is kept across a restart.** A message is accepted only once it is saved,
  so one the sender was told was queued survives a restart.
- **The core expires it.** On its own tick the core refuses every message held
  for the whole age: the trail's entry for it is marked **not delivered**, the
  sealed copy is deleted, and the sender can be told. The entry is marked before
  the copy is deleted, so a failure between the two loses nothing; the next tick
  finishes it, and each entry is marked once.
- **An add-on holds and delivers through it.** An add-on enqueues a sealed
  message and delivers it by the queue's own calls (`Enqueue`, `Held`,
  `Delivered`, `Kept`). It does not enforce the age and cannot lengthen it. The
  queue is not given without the trail the core marks in: the add-on names it
  when it takes the queue (`DeliveryQueue(trail)`), and a nil trail is refused.
  Each add-on names its own. A message is marked in the one trail that keeps its
  conversation; one that no trail keeps, or that several do, is left held and
  logged, never deleted unmarked.

The queue's numbers are the same limits an app is held to elsewhere
(`limits.Limits`); a phone scales the capacity and not the age.

## Why

An age limit that an add-on enforces holds only as long as every add-on does.
A sealed message cannot be read by the core, so the limit that matters is on
how long it stays, and that has to hold whatever an add-on does or fails to do:
the queue is therefore never given without the record the core marks in.
Marking the entry not delivered is a statement in the record about what
happened, so it is made by the part that keeps the record.

## Consequences

- A message undelivered after seven days is never silently lost: its entry says
  it was not delivered, and the sender is told.
- Every Identity Agent runs the expiry, whatever add-ons it includes.
- No add-on can hold a message the core cannot expire, because holding one
  needs a trail, and the queue it is given refuses a message for a conversation
  that trail does not keep. Nothing is deleted without being marked first, and a message
  whose record is not unambiguously one trail's is kept, not dropped; the queue's
  own bounds still limit what such a message costs.
