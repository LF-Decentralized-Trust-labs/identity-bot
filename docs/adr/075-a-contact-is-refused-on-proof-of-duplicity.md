# ADR-075: A Contact Is Refused on Proof of Duplicity

**Status:** Proposed
**Date:** 2026-11-12
**Deciders:** Rob Andersen
**Amends:** ADR-024 (KERI Network Participation)

---

## Context

An Identity Agent asks standing watchers whether the key history a stranger
shows it is the one they have seen. A standing watcher answers a signed digest.
From a bare digest the agent cannot tell a real fork from a watcher that is
broken or lying, so refusing on one watcher's digest lets any single watcher
freeze a person out of a contact, and refusing only when several watchers agree
needs several independent operators that do not exist yet.

KERI does not settle duplicity by counting. It settles it by evidence: two
events at one sequence number, both validly signed by the controller. A watcher
cannot forge that, because it does not hold the controller's keys. So the
question to put to a watcher that disagrees is not "how many of you agree" but
"show me your copy of the log".

## Decision

1. **A disagreeing watcher is asked for its log.** When a standing watcher's
   digest differs from the log a contact presented, the agent fetches that
   watcher's copy (`GET /witness/kel/{aid}`: each event as published, with its
   controller signature, and any rival events the watcher kept) and judges it
   itself. A watcher that agrees at the presented tip is also asked whether it
   holds an event after it, so a presenter showing an old key state is found.
   Nothing the watcher says is believed; everything is checked.
2. **The judging uses one validator.** The watcher's log must verify as a whole
   (self-certifying inception, every event signed by the key state in force), and
   each of its events the presented log lacks is admitted to the presented log
   with keri-go's `SignedKELResult.Admit`, the same rule a witness applies. No
   second validator is written.
3. **Proof refuses.** Two correctly signed events at one place, where `Admit`
   refuses the second as `FaultPlaceTaken` and the second verifies against the
   state before that place, are proven duplicity. One watcher's evidence is
   enough. The contact is refused (HTTP 409, code `duplicity`), and the alert
   stores both signed events, so anyone can check the fork without trusting this
   agent.
4. **A recovery rotation is not duplicity.** A rotation at a place already held
   replaces only the interactions after the last establishment event. If the
   watcher's log carries it, the presented log is stale and is replaced (item 6).
   If the presented log carries it, the watcher is merely behind: nothing is
   refused and the watcher is not flagged.
5. **A watcher whose branch does not verify is the faulty party.** Its answer is
   ignored for this contact, an alert is raised about the watcher (kind
   `watcher`, which blocks nothing), and the contact is not held. The same goes
   for a watcher that holds exactly the presented events yet gave another digest.
6. **A watcher that is ahead updates the key state.** Validly signed later
   events mean the presenter showed a stale key state, and a rotation may have
   retired the key it ends on. The agent adopts the latest verified log before it
   verifies or keeps anything signed, on every route that reads a log: OOBI
   resolve, add contact, credential verify and credential sign-in.
7. **What cannot be proven is shown, not acted on.** A watcher that withholds its
   log, cannot be reached, or disagrees while the presented log came without its
   signed bytes is the same as no watcher. The disagreement is shown to the owner
   as an escalation and refuses nothing. A delegated rotation at a place already
   held is not by itself duplicity (whether it may replace the held event turns
   on its delegator's log, which the agent does not have), so it is unprovable
   here and handled the same way.
8. **Standing watchers are for coverage, never a vote.** Any one honest watcher
   that holds what the controller published is enough to show a fork, so several
   raise the chance one does. Nothing counts watchers or operators to decide a
   refusal. An organisation is advised at least two standing watchers, and five
   to seven. There is no "held" state and no grouping of watchers by operator.
9. **A hosted watcher keeps and serves the other branch.** A watcher service
   keeps a correctly signed event that conflicts with the one it holds, as
   published, beside the first-seen one (which is never rewritten), and serves it
   with the log, so it can hand over the evidence. Its `first_seen_at` is when it
   saw the log through that place, from its own observations.

The agent's own record still refuses a repeat contact whose log differs from the
one this agent first saw (L1), as before.

## Consequences

- With one standing watcher, which is how an agent runs today, a real fork shown
  by that watcher refuses, and a watcher that is wrong cannot refuse anybody.
- A watcher that matches the presented log but also holds a rival branch is not
  asked for its log, since its digest says nothing of rivals; a fork it saw is
  shown to whoever presents the rival branch.
- A route to list standing watchers and the screens for proven duplicity and a
  flagged watcher are not part of this decision (see the watcher screens).
