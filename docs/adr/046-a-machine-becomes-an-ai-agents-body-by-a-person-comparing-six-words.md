# ADR-046 — A machine becomes an AI agent's body by a person comparing six words

**Status:** Accepted
**Date:** 2026-10-20
**Relates to:** ADR-044 (An authorized controller does the app's work), ADR-045 (Every asset gets an identity and a grant from one schema template)

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
   (66 bits of a Blake3 digest, BIP-39 English list). The owner compares the words in
   their app with the words on the machine and approves or rejects. A secret used by
   another machine shows other words. Rejecting returns a fresh string.
5. **A credential.** Approving issues an *AI Agent Body* credential (ADR-045 template)
   from the owner's registry. It says K is the body of this AI agent, at a grade.
   Revoking it is an event in the registry's log.

**Every request the body makes is signed by K** over the method, path, a timestamp and
a digest of the body. Each signature is accepted once, within two minutes. The gate
resolves the caller once and hands it to the handler, because a spent signature
cannot be checked twice. A body-signed request is the AI agent's: its grant decides
what it may do, and every recorded invocation names the body, its grade and its
credential.

**Grades are never above what was checked.** A body reports whether K is in secure
hardware. That report is recorded as *hardware (asserted)* — the machine's word. A
claim of an attested grade is clamped to the most the machine's own report supports,
and the clamp is recorded, until evidence for that grade is verified.

**One key is the body of one AI agent.** A machine hosting several AI agents uses a key
for each, so a signature always says which AI agent it speaks for.

**The machine key is the platform signer the Identity Agent already uses** for its own
controller key: the Secure Enclave on macOS (P-256), the TPM on Windows (P-256), a key
file elsewhere (Ed25519). The `agent-host` program carries it, and on macOS it is
built against the Secure Enclave shim, with the binary checked to contain it.

## Consequences

- An AI agent can run on a machine without any shared secret existing. Revoking the
  body stops that machine at once; the AI agent and its grant are untouched.
- Anybody holding the published logs, the body credential and its schema can check
  which machine key spoke for which AI agent, under whose approval, and at what grade.
- The bearer token remains for tools that cannot run `agent-host`, at the lowest grade.
- Requests after enrolment are signed, but not yet sealed: their content is readable
  wherever TLS ends. Sealing the body's ongoing messages arrives with AI agent
  messaging, which carries them in envelopes to the body's registered sealing keys.
- A machine's key in software, or one whose hardware report is false, is labelled only
  by its grade. Attested grades need platform evidence and are not yet verified.
