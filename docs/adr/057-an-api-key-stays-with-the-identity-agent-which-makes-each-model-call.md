# ADR-057 — An API key stays with the Identity Agent, which makes each model call

**Status:** Accepted
**Date:** 2026-10-28
**Amends:** ADR-051 (An AI agent's brain is signed in once, and lent to a body per run) and ADR-052 (A brain's sign-in is checked before it is kept, and capped per account): an API key for Anthropic, OpenAI, xAI or OpenRouter is no longer lent to a body; the body's brain makes its model calls through the Identity Agent, which adds the key. Subscriptions and model servers are still lent as before. An AI agent may also run with no program at all, its body calling the model itself.
**Relates to:** ADR-046 (A machine becomes an AI agent's body by a person comparing six words), ADR-047 (AI agents talk through the Identity Agent that holds them), ADR-050 (One check for a controller's actions and an AI agent's capability calls), ADR-056 (Revoking an AI agent is final)

## Context

ADR-051 lent an AI agent's sign-in to its body for one run, in the brain's
environment. For an API key that leaves three things open.

- **A body holds the key for as long as its run.** ADR-051 says so: a compromised
  body could copy what it was lent. An API key copied once works anywhere, for
  anyone, until somebody replaces it at its provider.
- **Taking the key away waits for the run to end.** Removing the sign-in,
  revoking the AI agent or letting its grant lapse stops the next lend, not the
  calls the run is making now.
- **Nothing records what a run used.** The body called the provider directly, so
  the Identity Agent saw neither the calls nor what they cost.

A subscription is different. Its provider's own program must hold it, and the
providers do not allow anyone else to use it, so it cannot stay behind. A model
server's key is often reachable only from the machines that run the AI agent.

## Decision

**An API key for a provider the Identity Agent can reach stays in its vault.** That
is a key for Anthropic, OpenAI, xAI or OpenRouter (and a Google key, which no
program runs yet). It is never lent to a body. The Identity Agent uses it itself,
for one model call at a time.

**The body's brain is pointed at the body.** A body that borrows such a sign-in is
lent a lease, as for any sign-in, and no key. It gives its brain:

- an address on the body's own loopback server, beside the host's tools;
- a token made for that run, which works nowhere else and is withdrawn when the
  run ends.

The program reads that address and token where it would read a provider's address
and key:

| Brain | Address | Token |
|---|---|---|
| Claude Code, an Anthropic key | `ANTHROPIC_BASE_URL` | `ANTHROPIC_AUTH_TOKEN` |
| Grok, an xAI key | `GROK_XAI_API_BASE_URL` | `XAI_API_KEY` |
| Grok, an OpenRouter key | its model settings for the run | the variable those settings name |
| Codex, an OpenAI key | its model provider, set on its command line | `CODEX_API_KEY` |

**The body passes each call on.** It sends the call to the Identity Agent sealed
and signed, as it sends everything, naming the lease its run holds. The Identity
Agent makes the call only when:

- the lease is open and held by that body for that AI agent;
- the AI agent may still act: not revoked, its grant not lapsed;
- its sign-in is still a key kept here.

It also makes only the calls a model key is for: the provider's model calls and its
list of models. Grok's program also asks xAI what its key is, which is answered too.
Nothing else the key could do is passed on.

The Identity Agent adds the key in the provider's own header. It sends the call the
way it sends its own model calls, with the same policy check, the owner's blocks on
where it may go, the proxy log and the trace. It follows no redirect. Of the brain's
headers, only those that describe the call travel on, and never how the brain proved
itself to its body.

**The answer streams.** Coding programs read a model's answer as it is written. A
sealed request is answered whole, so the Identity Agent runs the call in the
background. The body collects what has arrived, each collection waiting up to
twenty seconds for more, and writes it straight on to the brain. While a call is
under way, the Identity Agent checks at least every fifteen seconds that the run may
still make it, and stops it when it may not. A call nobody collects for ninety
seconds is stopped. No call runs longer than thirty minutes.

**Each call is recorded** in the signed governance record, as the AI agent, naming
the body: the call, the model, the provider's answer, how long it took, and the
tokens and cost where the provider reports them. A call refused, and an answer
stopped under way, are recorded with why. The key is never in the record.

**A body from before this cannot run such a brain.** A body says, when it borrows,
that it makes its brain's model calls through the Identity Agent. One that does not
say so is refused and told to update. It is never lent the key.

**An AI agent may run with no program.** Its brain's program is "none": it only
reads and answers. Its body calls the model itself, through the same address and so
through the Identity Agent. It has no tools and no use of the machine, and its words
are its answer. The conversation so far is kept in its workspace, one file per
session, so the next turn carries on from it. Only a key kept here can run this way.
A subscription is for its provider's program, and a model server's key is lent.

## Consequences

- A body never holds an API key, so a compromised body cannot copy one. While a run
  lasts, a compromised body can still make model calls with the run's lease, within
  the checks above, and every one is recorded.
- Removing the key, revoking the AI agent or ending its grant stops the next call,
  and stops an answer under way within fifteen seconds.
- What each AI agent spends is in the record, call by call, wherever the provider
  says it.
- Every model call crosses the Identity Agent, so a slow or unreachable Identity
  Agent slows or stops the AI agents that use keys kept there. A subscription or a
  model server is unaffected.
- One model call's request is at most 4 MB, because it travels sealed. A brain's
  conversation larger than that is refused by its body.
- A program that calls a provider at a fixed address, ignoring the one it is given,
  sends its run's token there. The token works nowhere else, and the call fails.
- Proven against the real programs, with a stand-in provider: Claude Code (2.1)
  with an Anthropic key, Grok's program (1.0) with an xAI key and with an OpenRouter
  key, and Codex (0.162) with an OpenAI key. Not yet proven against the providers
  themselves.
- Grok's program sends one of its own calls with its default model's name rather
  than the model it is set to. OpenRouter names models differently, so that call is
  expected to fail there; this is not yet seen against OpenRouter itself. The AI
  agent's own answers use the model it is set to.
