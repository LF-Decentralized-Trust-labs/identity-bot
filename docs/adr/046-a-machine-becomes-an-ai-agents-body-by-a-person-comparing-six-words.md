# ADR-046 — A machine becomes an AI agent's body by a person comparing six words

**Status:** Accepted; step 4, the six-word comparison, superseded by ADR-059 (2026-11-01)
**Date:** 2026-10-20
**Relates to:** ADR-044 (An authorized controller does the app's work), ADR-045 (Every asset gets an identity and a grant from one schema template)

> **Superseded in part, 2026-11-01.** A machine is no longer approved by a person comparing six words. It is approved from its own signed approval request, or on the vouch of the provider that made it (ADR-059). The six words are no longer derived or shown, and `agentbody.Words` is removed. The rest of this decision stands: proof of possession, the sealed enrolment, the one-time secret and the grades.

## Context

An AI agent's identity is held by its Identity Agent: a delegated identifier, and a
grant saying what it may do (ADR-045). Neither says where the AI agent runs. Software
acting as an AI agent on a machine has so far proved itself with a bearer token — a
shared secret anybody holding a copy can use, readable wherever a connection's
encryption ends.

The machine needs a key of its own, held in its secure hardware where it has any, and
a way to bind that key to one AI agent that a person approves and anybody can check
afterwards.

## Decision

**A body is a machine key, K, bound to one AI agent by a credential.** The AI agent's
own key never leaves its Identity Agent and its grant still decides what it may do. A
body only decides *where* a request may come from, and how strongly that is proven.

**Binding is a ceremony with a person in it:**

1. **An enrolment string.** The owner, or an authorised controller at the verified
   level, asks for one for a named AI agent. It carries:
   - the Identity Agent's address and identifier
   - one event in its key log
   - the AI agent
   - a one-time secret, valid for 15 minutes

   Issuing a new string voids the old one.
2. **The machine checks before it sends anything.** It fetches the Identity Agent's key
   log, and accepts it only if it is that identifier's, every event verifies, and it
   holds the named event. It then fetches the Identity Agent's sealing keys, and accepts
   them only if they are committed to, or signed by, the key that log ends with. An
   answer from a relay or a substituted address fails here.
3. **The enrolment is sealed and proves possession.** The machine signs with K, over the
   secret, a fresh nonce, the AI agent, the Identity Agent and all of its own public
   keys. It then seals the whole enrolment to the Identity Agent. The Identity Agent
   accepts only a sealed enrolment whose inner keys are the keys it was sealed from.
4. **Six words, compared by a person.** Both sides derive six words from K's identifier
   (66 bits of a Blake3 digest, BIP-39 English list). The machine shows its words
   before it sends anything, so its person has them even if the string was used first
   by someone else; on a refusal it tells them not to approve whatever is waiting. The
   owner compares the words in their app with the words on the machine and approves or
   rejects. A secret used by another machine shows other words. Rejecting returns a
   fresh string. A request nobody decides on before the string's 15 minutes run out
   expires and cannot be approved.
5. **A credential.** Approving issues an *AI Agent Body* credential (ADR-045 template)
   from the owner's registry. It says K is the body of this AI agent, at a grade.
   Revoking it is an event in the registry's log.

**Every request the body makes is signed by K** over the Identity Agent it is for (by
identifier), the method, the request target exactly as sent (escaped path and query), a
timestamp, a nonce, a digest of the body, the purpose it states for the record, and the
session it names, if any. An Identity Agent refuses a request naming any other, so a copy
is worthless at a second Identity Agent that has the same key enrolled. Each signature is
accepted once, within two minutes either side, and remembered for twice that. The gate
resolves the caller once and hands it to the handler, because a spent signature
cannot be checked twice. A body-signed request is the AI agent's: its grant decides
what it may do, and every recorded invocation names the body, its grade and its
credential.

**Grades are never above what was checked.** A body reports whether K is in secure
hardware. That report is recorded as *hardware (asserted)* — the machine's word. A
claim of an attested grade is clamped to the most the machine's own report supports,
and the clamp is recorded, until evidence for that grade is verified.

**One key is the body of one AI agent.** A machine hosting several AI agents uses a key
for each, so a signature always says which AI agent it speaks for. An AI agent may have
several live bodies — long-running servers, a replacement before the old machine is
removed — and each is removed on its own.

**Every step is in the signed record.** A machine asking, an approval, a rejection and a
removal are written as governance events, naming the AI agent, the body and its grade,
and who decided.

**Bodies are not carried in a backup.** Restoring one could bring back a body removed
after the archive was made; a body is enrolled again after a restore.

**The machine key is the platform signer the Identity Agent already uses** for its own
controller key, with the machine program's own data directory: the Secure Enclave on macOS
(P-256, a key per data directory), and a key file elsewhere (Ed25519). On Windows the
TPM key has one fixed name per machine and is already the Identity Agent's own, so a
body uses a key file there, at the software grade, until a per-body TPM key is built
and tested. On macOS the machine program is built against the Secure Enclave shim, with
each architecture's binary checked to contain it.

## Consequences

- An AI agent can run on a machine without any shared secret existing. Revoking the
  body stops that machine at once; the AI agent and its grant are untouched.
- Anybody holding the published logs, the body credential and its schema can check
  which machine key spoke for which AI agent, under whose approval, and at what grade.
- The bearer token remains for tools that cannot enrol a machine key, at the lowest grade.
- Requests after enrolment are signed and sealed: the machine's program carries each one inside
  the sealed transport, from the keys the body enrolled with to the Identity Agent's,
  so nothing between them reads the request or its answer (ADR-047, 2026-10-20). Only
  the enrolment status a machine asks while it waits for approval travels signed and
  unsealed, because until approval the Identity Agent takes no sealed request from it.
- A machine's key in software, or one whose hardware report is false, is labelled only
  by its grade. Attested grades need platform evidence and are not yet verified.

*Note, 2026-10-30: the program a machine runs to enrol and act as a body (formerly `agent-host` in this repository) is an add-on kept outside this repository. What it must do is this decision, the formats in `agentbody` and the published vectors in `contracts/agent-body`; any program that follows them can be a body.*
