# ADR-050 — One check for a controller's actions and an AI agent's capability calls

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
opens them to a controller. They are:

- the root of trust: rotating the identity's keys (directly, as a root rotation,
  or within a recovery), installing a root seed, resetting, founding the identity
  (by inception or hybrid inception), preparing the messaging keys an identity
  commits to, and bringing new owners in;
- the identity's key log: signing an interaction event, signing for the identity
  or taking up what its key device signed, fulfilling or refusing a signing request, and
  signing arbitrary data or an event as the identity;
- recovery: verifying a recovery archive, starting, activating or cancelling a
  recovery, setting who holds a recovery and the duress policy, and agreeing to
  hold, approving or giving up a share of somebody else's recovery;
- backups: retrieving, exporting or pulling back an archive;
- who may act: inviting and redeeming signers, adding or removing a controller,
  and approving a browser login;
- who the owner is: the identity record, key events, contact records and the
  routes that write them, the peer records a sealed request's sender is read
  from, the machine-owner identity, its signatures and adopting a machine, this
  computer's enclave signing, and which half this computer runs;
- what the key log is checked against and what the gateway trusts: adding a
  witness or watcher provider, and importing, enabling or deleting a capability;
- speaking as the identity to another Identity Agent by a sealed request, and
  installing software on this computer.

The list lives in one place, `controllerOwnerOnly` in
`identity-agent-core/server/what_a_controller_may_reach.go`, with a one-line
reason for each. Handlers do not re-check ownership for actions the gate opened
to controllers: a handler that needs to know its caller acts for the owner asks
`isOwnerOrItsController`, and an action that must stay closed to a controller
goes on this list instead.

**Every other action a controller takes, and every capability an AI agent
invokes, passes one check.** `sandbox.MayThisPersonDoThis` asks two questions in
order:

1. Is this person's identity score (0-100) at least the action's minimum? The
   minimum is `DefaultMinimumScore` (80) unless the action sets another: a
   capability by `minimum_score` in its registry record or manifest entry, a
   controller route in `controllerMinimumScore`. None is set today.
2. May this person do this action? A placeholder that always says yes until roles
   (owner, admin, employee) are built.

The controller path calls it for every route not on the owner-only list. The
governance gateway calls it where it authorises a capability invocation, after
ingress authorisation and before the action is recorded and run, and capability
discovery (the MCP tool list, search and describe) asks it too, so a capability
the caller would be refused is not offered. An AI agent's other requests — the
scoped HTTP routes it reaches with its token — are governed by its grant's scopes
as before and do not pass this check.

**The check compares scores, never named levels.** A badge (green at 80 and
above, amber 40-79, red below 40) and a level are derived from the score for
display, and never the other way round, because a badge cannot be turned back
into a score. A vouched statement's level is derived from its score in the same
way.

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
- A controller can create tokens, AI agents, AI agent bodies and member approvals
  that keep working after the controller's grant is revoked or expires. Each is
  recorded against the controller that made it (`made_by_controller` on a token
  and an AI agent, `approved_by_controller` on a member, `decided_by` on a body).
  Removing them when the controller is revoked is future work.
- While the placeholder stands, a controller can avoid a low vouched score by
  sending no statement at all, and is then judged at 80. A vouched score is
  meaningful only once real human authentication replaces the placeholder; then
  a missing statement must count as nothing measured.
- A controller can publish or withdraw where one of the identity's pairwise
  identities is reached, so a compromised one can stop messages arriving on
  that relationship until the owner publishes again.
- Removing a machine (`DELETE /api/controllers/{aid}`) is owner-only, so a stolen
  laptop is removed from the device holding the identity's key, not from another
  computer.
- An action can be made harder to reach by setting its minimum above 80; with
  the placeholder in place, that action is closed to everybody without a vouched
  statement that meets it.
- Replacing the placeholder with real human authentication, or the permission
  placeholder with roles, changes one function each and nothing that calls them.
- The earlier design kept rotation reachable from a controller, at the strongest
  level, so that a stolen key device would not leave the identity unrotatable.
  That level was never reachable, and rotation is now owner-only by decision
  rather than by accident.
