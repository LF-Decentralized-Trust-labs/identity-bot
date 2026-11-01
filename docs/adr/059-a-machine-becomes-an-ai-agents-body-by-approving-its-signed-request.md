# ADR-059 — A machine becomes an AI agent's body by approving its signed request, not by comparing six words

**Status:** Accepted (2026-11-01)
**Date:** 2026-10-29
**Supersedes in part:** ADR-046 (step 4, the six-word comparison), the per-machine human approval of a machine a provider made (a provider is a program that makes machines for AI agents on request; how it does so is that runtime's own decision, kept outside this repository)
**Relates to:** ADR-044 (an authorized controller does the app's work), ADR-050 (one check for a controller's actions and an AI agent's capability calls)

**Rollout.** Built in phases: the signed-request approval path first, alongside the six-word flow, then the provider vouch, then (2026-11-01) the removal of the six-word derivation and comparison, with the supersession note on ADR-046.

## Context

A machine becomes an AI agent's body by proving possession of its key K and binding it to one AI agent with a credential a person approves (ADR-046). The approval step put a person in the middle to compare six words derived from K — shown on the machine and in the approver's app — so that a stolen one-time enrolment string, used by a different machine, would show different words and be rejected.

That comparison does real work in exactly one case: a person setting a machine up by hand, reading the words off the machine's own screen. It is the reading-off-the-machine that ties "the machine in front of me" to "the key that asked." When a machine is made by a provider, nobody reads its screen — the provider reports the words, so the approver compares two values the same software produced, which proves nothing. The comparison is also fragile: it is timing-sensitive (a provider that reported the words a moment before the machine's request arrived could have the machine refused and then destroyed), and asking people to match word lists on every machine trains them to approve without looking, eroding the one case where the check matters.

## Decision

**The six-word comparison is retired, in favour of approving the machine's own signed request.** K is still proven by possession and the enrolment is still sealed (ADR-046, otherwise unchanged). What changes is how the binding is approved.

**A machine a person sets up is approved from its own signed request.** The machine produces a request carrying K's identifier and K's signature over what it is asking for — the AI agent, the Identity Agent, the one-time secret, and a fresh nonce. The request is self-verifying: anyone can check it was made by the holder of K. An authorized approver — the owner, or an authorized controller (ADR-044, ADR-050) — takes this request into their Identity Agent, which verifies K's signature and shows what is being approved, and the person approves in one action. Approving binds exactly the K the request carries.

**Because the request proves itself, how it reaches the approver carries no authority and is not part of the protocol.** It may be pasted, read off the machine's screen by a camera, or relayed by another device the person holds. A tampered copy fails signature verification. A copy of someone else's request binds their K, not the machine in front of the person — and it is simply not the one the person captures. This replaces a comparison done by a person's eyes with a check done by the Identity Agent, and leaves the person only the decision.

**A machine a provider makes is approved on the provider's signed vouch.** A provider is an enrolled body with a proven key, handed the one-time secret sealed to its keys. For a machine it made for a request, the provider signs a statement binding K to that request and that enrolment string. The Identity Agent approves on the vouch, with no per-machine human step, and records the provider as the approver. The per-machine human decision becomes a standing one — which providers may make machines — settled once when a provider is granted.

**Grades are unchanged.** Approval decides that K is this AI agent's body and who approved it; it never raises the grade. A machine's grade is still the most its own hardware report supports until attested evidence is verified (ADR-046).

**Every step stays in the signed record** — the machine's request, the approval or its refusal, and who approved (a person, or a provider) — as before.

## Consequences

- A person approves a machine by capturing its request once, not by comparing two word lists, so there is no transcription error and no habit of approving an unread comparison. The protection against a stolen enrolment string is unchanged: the person captures the request from the machine in front of them, and a thief's machine, elsewhere, is never captured and expires.
- A provider-made machine needs no person present at approval, which is what lets machines be made at scale. The trust rests where it already did — on the proven provider — now stated and recorded rather than dressed as a human check.
- The timing fault that could refuse and destroy a machine when its words were reported early no longer exists, because no words are shown or compared.
- The six-word derivation and the approver-side comparison are removed once this lands in full (`agentbody.Words` and the comparison surface); see Rollout.
- A device that only captures a request needs no authority of its own, because the request proves itself; the authority to approve remains the owner's or an authorized controller's, checked the one way (ADR-050). This is what lets a capture device — a camera, or another of the person's apps relaying the request — feed an approver that holds the authority, without being granted any.

ADR-046 carries the note recording which part of it this supersedes (see Rollout).
