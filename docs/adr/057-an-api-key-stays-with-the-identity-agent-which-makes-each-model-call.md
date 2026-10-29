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
| ~~Grok, an OpenRouter key~~ | ~~its model settings for the run~~ | ~~the variable those settings name~~ |
| agent-host's own loop, any key kept here (*amended by ADR-058*) | `AGENT_HOST_MODEL_URL` | `AGENT_HOST_MODEL_TOKEN` |
| Codex, an OpenAI key | its model provider, set on its command line | `CODEX_API_KEY` |

**The body passes each call on.** It sends the call to the Identity Agent sealed
and signed, as it sends everything, naming the lease its run holds. The Identity
Agent makes the call only when:

- the lease is open and held by that body for that AI agent;
- the AI agent may still act: not revoked, its grant not lapsed;
- its sign-in is still a key kept here.

It also makes only the calls a model key is for: the provider's model calls, its list
of models, and one model by name. Grok's program also asks xAI what its key is, which
is answered too. The path must be plain and short — nothing escaped, no fragment,
nothing that cleaning it would change — so what is checked is what is sent. A query
may carry only the parameters a model call uses: `beta=true`, as Claude Code sends,
and the paging of a list of models. Nothing else the key could do is passed on.

*Amended 2026-10-29.* **Only the chosen model is called.** When a model is chosen for
the AI agent, a model call must name exactly that model: one naming another, or none,
or a list of models to fall back on, is refused before it reaches the provider, and
recorded. The call must be one JSON object naming its model once, as `model` exactly,
so the provider cannot read another model from the same bytes than the one checked.
It is refused rather than rewritten to the chosen model, because the
Identity Agent passes on what the brain sent and checks what it sends: rewriting a
call would answer a request the brain never made, at a price nobody chose, and hide
the program that made it. So whatever program runs the brain, it can spend the key
only on the model chosen. Listing models, or asking about one by name, costs nothing
and is not held to the chosen model. An AI agent with no model chosen makes the calls its
program makes.

One machine may hold at most eight calls here for its AI agent, whichever leases they
cite: a call counts from when it starts until its whole answer is collected or it is
swept away. What every answer holds before it is collected is bounded across all
calls, and a call that would pass the bound is stopped; so is how many calls are kept
at once across every machine.

**The key never travels back.** A provider can quote what it was sent, in an error
above all. Every answer is read for the key as it arrives, holding back the last few
bytes until more comes so a key split across two parts is still seen whole, and a call
whose answer carries the key is stopped before any of it is passed on.

The Identity Agent adds the key in the provider's own header. It sends the call the
way it sends its own model calls, with the same policy check, the owner's blocks on
where it may go, the proxy log and the trace. It follows no redirect. Only the headers
that describe the call travel on — its content type, what it accepts, and the
providers' version and feature headers — whatever the body sent, and never how the
brain proved itself to its body. The body and the Identity Agent pass the same list.

**The answer streams.** Coding programs read a model's answer as it is written. A
sealed request is answered whole, so the Identity Agent runs the call in the
background. The body collects what has arrived, at most 2 MB at a time, each
collection waiting up to twenty seconds for more, and writes it straight on to the
brain. While a call is under way, the Identity Agent checks every fifteen seconds,
whether or not the body is collecting, that the run may still make it, asking afresh
each time what the AI agent may do. When it may
not, it stops the call, and with it the provider's answer and what that costs. No
call runs longer than thirty minutes.

*Amended 2026-10-29.* **A call let go is read to its end.** A call its brain gives up
on, a call still under way when its run ends, and one nobody collects for ninety
seconds are let go: nothing more of the answer is held or passed on, but the answer is
read to its end, so what the provider says the call used and cost is recorded. A call
let go counts against its body until it ends, and is still stopped at once when the AI
agent may no longer act or its key is removed or replaced. Finishing it costs no more
than the answer the brain itself asked for; an answer that runs past 16 MB more once
let go is cut, and recorded as cut.

**A renewed lease carries the call.** A run whose lease lapsed takes another
(ADR-051). A call under way goes on under the new one, so long as the same body
holds it.

**A call the Identity Agent no longer knows is a failed call.** The calls under way
are held in memory. If the Identity Agent restarts, a call it was making is lost: the
body tells its brain the call failed, and the brain's program makes it again, as it
does for any failed call.

**Each call is recorded** in the signed governance record, as the AI agent, naming
the body: the call, the model, the provider's answer, how long it took, and the
tokens and cost where the provider reports them. A call refused, and an answer
stopped under way, are recorded with why. The key is never in the record. What a body
sends is recorded only as one short printable line, and at most twenty of one body's
refusals are recorded a minute, so a body cannot fill or forge the record.

*Amended 2026-10-29.* **An AI agent's model calls may be given an allowance.** The
owner's app, or a controller, may give an AI agent an amount, in its provider's
currency, that its model calls may cost (`PUT /api/mcp/agents/{id}/model-allowance`).
It is how a person caps what a run spends, such as a benchmark or a worker left on its
own, so that nothing on the AI agent's machine can spend past it.

- **Counting:** each call's cost is counted against the allowance once its answer ends,
  as the provider says it.
- **One call at a time:** a call's cost is known only at its end, so while an allowance
  is set the AI agent makes one model call at a time, across every machine. A call is
  refused while another is under way or not yet counted.
- **Refusal:** once what is spent reaches the amount, the next call is refused, and
  recorded. What is spent can pass the amount by at most the one call that crossed it.
- **A bounded call:** under an allowance a model call must say how long an answer it
  wants, at most 32,768 tokens, each way of saying it at most once, so that one call
  is bounded too: what it reads is bounded by how large a call may be. agent-host's own
  calls always say it.
- **A lost call:** the call under way is written down before it is sent. One still
  written down that the Identity Agent no longer knows was lost when it restarted, and
  what it cost is not known, so every call after it is refused until a person sets the
  allowance again.
- **Changing it:** a new amount keeps what was spent, unless the person starts over. An
  amount of nothing stops the next call. Removing the allowance lifts the cap.
- **When the cost is not said:** a call the provider answered without saying what it
  cost leaves what is left unknown, so every call after it is refused until a person
  sets the allowance again.
- **Where it can be set:** only on a key kept here, from a provider that says what each
  call costs (OpenRouter does). Elsewhere it is refused rather than pretended.
- **Where it is kept:** in the vault, with each counted call (its model, the provider's
  id for it, its tokens and cost), so a restart forgets nothing.
- **What is recorded:** setting, changing, spending and removing it, with who set it
  and what it was before. A session may not set it, because it outlives the session.

**A body from before this cannot run such a brain.** A body says, when it borrows,
that it makes its brain's model calls through the Identity Agent. One that does not
say so is refused and told to update. It is never lent the key.

**An AI agent may run with no program.** Its brain's program is "none": it only
reads and answers. Its body calls the model itself, through the same address and so
through the Identity Agent. It has no tools and no use of the machine, and its words
are its answer. The Identity Agent holds it to that as well as its body: it lends it
no GitHub access, and refuses its asking another AI agent. The conversation so far is kept in its
workspace, one file per session and at most 1 MB, the oldest turns let go first, so
the next turn carries on from it. A turn whose conversation cannot be read or kept
fails rather than carrying on without it. Only a key kept here can run this way: a
subscription is for its provider's program, and a model server's key is lent. A
sign-in such an AI agent cannot run with is refused when it is set.

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
- One model call's request is at most 3 MB, because it travels sealed, base64-encoded
  three times over, in an envelope of at most 8 MB. A brain's conversation larger
  than that is refused.
- Calls under way are lost when the Identity Agent restarts. The brain sees each as a
  failed call and makes it again.
- A program that calls a provider at a fixed address, ignoring the one it is given,
  sends its run's token there. The token works nowhere else, and the call fails.
- Proven against the real programs, with a stand-in provider: Claude Code (2.1)
  with an Anthropic key, Grok's program (1.0) with an xAI key and with an OpenRouter
  key, and Codex (0.162) with an OpenAI key. Not yet proven against the providers
  themselves.
- *Amended 2026-10-29.* Grok's program sent one of its own calls under its default
  model rather than the one it was set to, and against OpenRouter that call was
  answered and paid for. A call naming any model but the chosen one is now refused
  here; a program that makes such calls sees them fail.
- *Amended 2026-10-29.* While an allowance is set an AI agent's model calls run one at
  a time, so a program that makes calls side by side sees the extra ones refused and
  makes them again. That is the price of a cap that holds to within one call.
- A call let go is paid for in full, where cutting it off would have saved the rest of
  its answer: knowing what every call cost is worth more than that.
