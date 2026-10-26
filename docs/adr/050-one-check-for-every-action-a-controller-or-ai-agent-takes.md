# ADR-050 — One check for every action a controller or an AI agent takes

**Status:** Accepted
**Date:** 2026-10-26
**Amends:** ADR-044 (An authorized controller does the application's work; the owner key does the root of trust)
**Relates to:** ADR-043 (A developer mode rooted in a separate trust anchor), ADR-045 (Every asset gets an identity and a grant from one schema template)

## Context

ADR-044 split a controller's authority into the root of trust, which only the
owner key may touch, and the application's work, which an authorised controller
may do. In code the split was a table of 56 routes, each either closed to a
controller or *raised* to a named authentication level (`verified` or `high`)
that the person at the controller had to reach, proven by a statement the device
holding the identity's key signed.

Nothing produces that statement yet: measuring the person, and having the key
device vouch for the result, is not built. So in practice every raised route was
closed. A controller could not create an AI agent, mint its token, issue a
credential, or change where backups go. A development build stood in for the
missing measurement, calling an unmeasured controller `verified` when nothing
outside the computer could reach it, which made development and production
authorise differently.

Separately, an AI agent's capability invocations were judged by the governance
gateway with no identity requirement at all. Two paths, two rules, for the same
question: may this person do this action.

## Decision

**A controller may do every action except an owner-only list.** The owner-only
actions are done with the owner's keys, on the device holding them, and no score
opens them to a controller. They are: rotating the identity's keys (directly, as
a root rotation, or within a recovery), installing a root seed, resetting,
founding the identity, starting, activating or cancelling a recovery, setting who
holds a recovery and the duress policy, inviting and redeeming signers, adding or
removing a controller, retrieving, exporting or pulling back a backup archive,
signing arbitrary data or an event as the identity, fulfilling a signing
request, and every write that decides who the owner is (the identity record, key
events, contact records and the routes that write them, the machine-owner
identity and its signatures, this computer's enclave signing and which half it
runs). The list lives in one place, `controllerOwnerOnly` in
`identity-agent-core/server/what_a_controller_may_reach.go`, with a one-line
reason for each.

**Every other action passes one check, the same for a person at a controller and
for an AI agent.** `sandbox.MayThisPersonDoThis` asks two questions in order:

1. Is this person's identity score (0-100) at least the action's minimum? The
   minimum is 80 unless the action sets another: a capability by `minimum_score`
   in its registry record or manifest entry, a controller route in
   `controllerMinimumScore`. None is set today.
2. May this person do this action? A placeholder that always says yes until roles
   (owner, admin, employee) are built.

The controller path calls it for every route not on the owner-only list. The
governance gateway calls it where it authorises a capability invocation, after
ingress authorisation and before the action is recorded and run.

**The check compares scores, never named levels.** A badge (green at 80 and
above, amber 40-79, red below 40) and a level are derived from the score for
display, and never the other way round, because a badge cannot be turned back
into a score.

**Until human authentication is built, every person scores 80.** One function,
`authprovider.UntilHumanAuthenticationIsBuilt`, returns a measured result with
score 80 and provider `placeholder-until-human-authentication`. A controller's
request that carries a statement vouched for by the key device, made within the
last five minutes, uses that statement's score instead. An AI agent's score
comes from the same placeholder.

**Development and production builds authorise identically.** The
development-only stand-in is removed. What differs between the builds is
attestation and its trust anchor (ADR-043), and nothing else.

**Machines authorised before grants were recorded are re-granted by the owner,
never automatically.** This is unchanged from ADR-044 as amended on 2026-10-22:
nothing in the grants file tells such a machine apart from a row somebody added
to it, so start-up grants nothing.

## Consequences

- A controller can create and manage AI agents, mint their tokens, issue and
  revoke credentials, manage stored keys and backup destinations, and approve
  employees, without a statement nothing can yet produce.
- An action can be made harder to reach by setting its minimum above 80; with
  the placeholder in place, that action is closed to everybody without a vouched
  statement that meets it.
- Replacing the placeholder with real human authentication, or the permission
  placeholder with roles, changes one function each and nothing that calls them.
- The earlier design kept rotation reachable from a controller, at the strongest
  level, so that a stolen key device would not leave the identity unrotatable.
  That level was never reachable, and rotation is now owner-only by decision
  rather than by accident.
