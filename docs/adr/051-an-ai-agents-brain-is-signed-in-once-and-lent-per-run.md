# ADR-051 — An AI agent's brain is signed in once, and lent to a body per run

**Status:** Accepted
**Amended by:** ADR-052 (A brain's sign-in is checked before it is kept, and capped per account), 2026-10-26; ADR-057 (An API key stays with the Identity Agent, which makes each model call), 2026-10-28
**Date:** 2026-10-26
**Relates to:** ADR-045 (Every asset gets an identity and a grant from one schema template), ADR-046 (A machine becomes an AI agent's body by a person comparing six words), ADR-047 (AI agents talk through the Identity Agent that holds them), ADR-050 (One check for a controller's actions and an AI agent's capability calls)

## Context

An AI agent thinks with a brain: a program such as Claude Code or Grok, run by its
body for one message at a time (ADR-047). The brain needs a sign-in to reach its
model — a provider's API key, a person's subscription, or the address of a model
server the organisation runs.

Until now the sign-in was wherever somebody put it. A key typed when the AI agent was
created was stored on the AI agent's record as typed and returned in every view of the
AI agent, although the record's own description said it held only a reference. A
subscription was signed in by a person typing a sign-in command on each machine, where
it stayed. The brain's name was stored as a screen showed it, which no machine
recognised.

A sign-in kept on a machine is a copy nobody governs: it outlives the machine's
approval as a body, it cannot be replaced from one place, and nothing records which
runs used it. A subscription is also meant for one person's use, and nothing stopped
one being driven by any number of machines at once.

## Decision

**A brain's sign-in lives in the Identity Agent's vault, and nowhere else.** It is
one record per AI agent, holding:

- its kind: an API key, a subscription, or a local model server;
- the provider: anthropic, openai, google, xai, openrouter, claude-code, codex, grok or
  local;
- a label for whose account it is, when it expires, and a local server's address;
- the cap on simultaneous runs;
- the key or token itself.

The AI agent's record holds only a reference to it. The key or token is never returned
by any route a person or a front end reads. Setting, replacing or removing a sign-in is
the application's work, open to the owner and to an authorised controller (ADR-050).

**A key sent where the reference belongs is moved into the vault.** Creating an AI
agent or changing its configuration with a key in the brain's reference field keeps the
key in the vault and stores the reference in its place. If the vault cannot be
written, nothing is created or changed rather than the key being stored elsewhere. Any
key an earlier version stored on an AI agent's record is moved into the vault at start,
and again whenever AI agents are listed or a body borrows, until none is left, because
the vault's key may only be present after setup. Until then such a key is never shown. Moving a
secret the Identity Agent already holds into its vault grants nothing to anybody, so it
needs no decision by the owner.

**A key is never sent in a request that is kept as signed.** A signed request to create
an AI agent is kept with the grant it authorises, exactly as signed, and goes with that
grant wherever the grant is shown or exported (ADR-045). A key in that request would go
with it, so such a request is refused and nothing is created. The sign-in is sent on its
own once the AI agent exists, to a route that keeps only the vault entry.

**A sign-in is lent to a body for one run.** When a run starts, the body asks for its
AI agent's sign-in, signed by its machine key and sealed to the Identity Agent
(ADR-046). The answer travels sealed back to the keys that body enrolled with. It
carries the sign-in and a lease. The body puts the sign-in in the brain's environment
for that run alone: never on a command line, never in a file. When the run ends, or
fails, the body returns it.

*Amended by ADR-057:* an API key for Anthropic, OpenAI, xAI or OpenRouter is not lent.
The body is lent the lease alone, and its brain makes its model calls through the
Identity Agent, which adds the key to each.

**A lease lapses unless renewed.** It holds for five minutes and the body renews it
while the run goes on, so a machine that crashed mid-run frees its place without
anybody returning it. A run whose lease lapsed anyway takes a place again.

**Only an AI agent that may act is lent its sign-in.** An AI agent whose grant is
revoked or has lapsed is lent nothing, and its lease is not renewed, though its body
still stands.

**Each sign-in has a cap on simultaneous runs, across every machine.** The default
is:

- ~~5 for a subscription;~~
- 1 for Codex, whose sign-in cannot be shared between runs;
- none for an API key or a local model server.

*Amended by ADR-052:* 5 for a Claude subscription, and 1 for a Grok subscription as
for Codex, because both renew their own sign-in while they run. A subscription's cap
is never none.

The owner may set another number. A body asking past the cap is told the sign-in's runs
are in use, and waits.

*Amended by ADR-052:* the cap counts every run on the sign-in's account, across every
AI agent signed in to it, and is one number for the account.

**Every lend, refusal, return and lapse is written to the signed governance record**,
as the AI agent, naming the body, and never with the secret. A lapse is written when
the Identity Agent next lends, renews or takes back a sign-in.

**The brain's name is the program that runs it.** A configuration's kind and provider
are normalised when stored, and a body accepts the names a screen shows as well. The
provider decides the program:

- Claude Code runs a Claude subscription, an Anthropic key and a local model server;
- Grok's program runs an xAI key;
- ~~Codex would run OpenAI.~~

*Amended by ADR-052:* Codex runs an OpenAI key and a ChatGPT plan, and Grok's program
also runs a Grok plan, OpenRouter and servers that speak OpenAI's format.

**An AI agent with no sign-in in the vault runs as before**, with whatever its machine's
brain was signed in with by hand, and the body logs that it did.

## Consequences

- A sign-in is replaced or removed in one place, and the next run on every machine uses
  the new one. Revoking a body ends its access to the sign-in at its next run.
- The record shows which body held which AI agent's sign-in, and when.
- A body may hold a sign-in for as long as a run takes. A compromised body could copy
  what it was lent during that run; the lease limits when it can borrow, not what it
  does with what it holds. *Amended by ADR-057:* this no longer holds for an API key,
  which a body is never lent.
- Claude Code reads a subscription token only when it is not run in its bare mode, so
  the body never asks for that mode.
- A local model server is given a stand-in key when it needs none, so the brain never
  sends the machine's own sign-in to that server's address.
- A key sent in a signed request to create an AI agent before this decision is still in
  that kept request, and goes with its grant when the grant is exported. Taking it out
  would break the signature the request is kept to prove, so it is left; the key itself
  should be replaced at its provider.
- ~~A cap counts runs of one AI agent's sign-in. The same account signed in for two AI
  agents is two sign-ins, each with its own cap, so the runs on one account can exceed
  any one cap.~~ *Amended by ADR-052:* a cap counts every run on the sign-in's account,
  whichever AI agent holds it.
- A borrowed sign-in replaces every sign-in in the machine's environment, but not one
  in the brain user's own configuration: a key helper in Claude Code's settings~~, or a
  session from Grok's own sign-in,~~ outranks it. *Amended by ADR-052:* Grok and Codex
  run in a home of the body's making, so their own sign-in and settings do not.
- ~~Not yet lent to a body: a Codex sign-in, a Grok subscription, and OpenAI, Google or
  OpenRouter keys. The programs that run them need either a sign-in file rather than an
  environment variable, or configuration not yet written.~~ *Amended by ADR-052:* all
  but a Google key are lent.
- ~~Signing a subscription in from a front end, without a terminal, and checking a
  sign-in works with a test call when it is made, are not yet built.~~ *Amended by
  ADR-052:* a sign-in is checked when it is made. A front end signs a subscription in
  without a terminal by running the provider's own program on the person's computer.
