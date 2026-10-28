# ADR-056 — Revoking an AI agent is final

**Status:** Accepted
**Date:** 2026-10-28
**Relates to:** ADR-045 (Every asset gets an identity and a grant from one schema template), ADR-046 (A machine becomes an AI agent's body by a person comparing six words), ADR-050 (One check for a controller's actions and an AI agent's capability calls), ADR-055 (A new machine for an AI agent is made by a provider, and approved by a person)

## Context

An AI agent can do only what its grant says. Revoking that grant credential stops it.
But nothing stopped a later change from issuing a new one: saving what the AI agent
may do, or which repositories it may use, re-issues its grant. That brings a revoked
AI agent back to life without anybody deciding to. Revoking also meant finding the
grant credential and revoking it by number, and the machines that ran the AI agent
kept their bindings.

## Decision

**One action revokes an AI agent: `POST /api/mcp/agents/{id}/revoke`.** It does
four things, in this order:

1. It marks the AI agent revoked on its record, with the time and who did it.
2. It withdraws every grant the AI agent holds, writing each one to the registry.
3. It ends every machine that is the AI agent's live body, and withdraws that
   body's credential. It refuses any machine still waiting for approval.
4. It has the machines a provider made for the AI agent destroyed (ADR-055).

The mark comes first, so a change arriving while the grants are being withdrawn
cannot issue a new one. A step that cannot be written yet is reported, and asking
again retries it.

**The mark is what refuses it.** From the mark onward the AI agent is resolved with no
scopes, whether it calls with its token, by its own signature or through a machine, so
it can do nothing even while a grant's withdrawal is still being written, or if a grant
that was waiting for another device is signed later. Its status is "revoked". The mark
is kept in a record of its own, not on the AI agent's record, so a change to that
record that was read before the revocation and written after it cannot remove it.
Nothing removes a mark.

**A revoked AI agent is never granted anything again, or set up again.** These are
refused with 409:

- any change that would re-issue its grant: what it may do, which repositories it may
  use;
- changing its configuration or its brain's sign-in;
- a new enrolment string, approving a machine, and a machine enrolling;
- a person's or another AI agent's message to it.

Its identity, its record and the signed history of what it did are kept, so all of it
can still be checked.

**To use an AI agent like it again, a person creates a new one.** The new AI agent
gets a new identity, so nothing it does can be mistaken for the old one's.

**Who may do it.** Revoking takes nothing from the owner, so it is not owner-only. A
controller may do it after the one check (ADR-050), and it is recorded against that
controller. A browser session may not, because revoking cannot be undone and outlives
the session.

## Consequences

- Revoking an AI agent is one action a front end can offer, behind a confirmation.
- Lists of AI agents carry `revoked_at` and `revoked_by`. A front end can show a
  revoked AI agent as revoked and offer nothing that would act for it. Status
  "revoked" without `revoked_at` means its grant was withdrawn, which a new grant can
  replace; that is not this.
- Revoking holds the AI agent's lock while it writes to the registry, so other changes
  to that AI agent wait for it.
- There is no un-revoke. Undoing a mistaken revocation means creating a new AI agent
  and granting it what the old one had.
