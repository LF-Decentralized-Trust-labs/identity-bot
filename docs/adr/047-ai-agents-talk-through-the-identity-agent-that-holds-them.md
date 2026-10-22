# ADR-047 — AI agents talk through the Identity Agent that holds them

**Status:** Accepted
**Date:** 2026-10-20
**Relates to:** ADR-044 (An authorized controller does the app's work), ADR-045 (Every asset gets an identity and a grant from one schema template), ADR-046 (A machine becomes an AI agent's body by a person comparing six words)

## Context

An AI agent has an identity, held by its Identity Agent, and a body: a machine whose
key speaks for it (ADR-046). The next thing people need is for AI agents to work
together. A person asks one AI agent for something, that AI agent asks another, and
the answer comes back.

The conversation has to be provable afterwards. It must show who started it, who said
what, under whose authority, and from which machine. As much of that as possible must
hold even for someone who does not trust the Identity Agent. It also has to be governed. An AI agent acting for
a person must not reach further than that person can, and two AI agents must not talk
forever.

## Decision

**Every message goes through the Identity Agent, in both directions.** That covers a
person to an AI agent, one AI agent to another, the answer back, and the answer to the
person. Nothing travels from one machine to another directly. Each body only dials out
to its Identity Agent, so no machine listens for connections.

**A person asks an AI agent, never the organisation.** The person must be someone the
organisation can prove. In this version that is a signer of the organisation, speaking
through a controller the owner paired (ADR-044). The owner the organisation's own key
log names counts as a signer whether or not they are on its roster, since that log is
the strongest proof of a person it has; the record marks them as the owner, and they
stop standing when the log names somebody else. The controller grant names its signer:
the one the owner's device named when it paired the machine, or else the organisation's
only signer at that moment. A person's message is recorded with their
controller's signature over the request.

**The Identity Agent owns the conversation.** It opens a conversation when a person
speaks, and chooses its identifier. A body speaks only:
- inside a conversation it has been brought into;
- and only about a message it was given there.

A body cannot open a conversation. Otherwise a body could escape a person's limits by
starting a conversation of its own, or by borrowing one somebody with wider access
opened.

**What each message may do is checked at the Identity Agent:**
- **An ask.** The asking AI agent's grant must include `agent.message.send`. Its
  constraint on `to`, if any, must name the AI agent asked. The person who opened the
  conversation must also be allowed to reach that AI agent. An AI agent acting for a
  person reaches no further than the person.
- **A reply, or a failure notice.** It must name the ask it answers. It goes only to
  that ask's sender, and the ask must have been addressed to the one replying. A reply
  cannot reach anybody new.
- **A receipt.** It must name a message given to the body sending it.

An ask is answered once by the party it was put to. The answer is a reply or a failure
notice, and a second one is refused. Otherwise one body could make another's brain run
again and again.

A conversation holds at most 40 asks, replies and failure notices. Asks stop there; an
answer to an ask already made is never refused for want of a turn. A chain of asks goes
at most three deep. It closes after 30 minutes with nothing said. A receipt is not
something said: it neither counts as a turn nor keeps a conversation open. A receipt is
taken only for a message still waiting for the body that sends it. These limits are
checked inside the same transaction that writes the entry, so two senders at once
cannot race past them.

The opener's standing is checked again on every ask made in their conversation, not
only when they opened it.

Every refusal of a message from a person or a body is written to the signed governance
record. So is a person opening a conversation's record, and a body reading one back. A
person's later waits for news in a conversation they already opened are not recorded
one by one.

*Amended 2026-10-22.* Every message the record takes is written to the signed governance
record as well, and so is every handing of a message to a body, so the log shows what
was sent and delivered and not only what was refused. Each of these rows, and each
refusal that names a conversation, is filed under that conversation as its work item,
so one conversation's whole history is read from the log by asking for it.

**Every message is signed twice, for two different claims:**
1. **The sender's own statement.** A body signs it with its machine key over a
   fixed, line-separated string. The string covers the conversation, the kind of
   message, from and to, the message it acts on, a digest of the words, what brain
   produced them, a nonce, a time, and the body's credential. A person's controller
   signs their request. The Identity Agent never holds either key, so it cannot forge
   this layer.
2. **The Identity Agent's countersignature, as the party the message is from.** For an
   AI agent's message, that AI agent's own messaging keys sign it. Those keys are
   vouched for by its key-log key. For a person's message, the Identity Agent's own
   keys sign it. The countersignature covers the sender's statement and its signature,
   plus what only the Identity Agent knows:
   - the message's place in the conversation;
   - the hash of the entry before it;
   - the grant that allowed it;
   - the grade of the body it came from, stamped here so a body cannot talk itself up.

The countersigned entry is a signed DIDComm message (`agent-message`). Its hash is the
next entry's `prev_hash`, so each conversation is a hash chain.

**The words travel beside the signatures, not inside them.** Both layers sign the
words' digest. So the words can be kept wherever the organisation chooses (a content
store: on the Identity Agent by default) and still be checked against the record.

**A body checks what it is given before acting on it:**
- the countersigner's keys belong to that identity, by its published key log;
- the countersigner is the Identity Agent itself, or an AI agent it delegated;
- the countersignature holds;
- the sender's own signature holds, against the key the entry names;
- the words match their digest;
- the message is addressed to this body's AI agent.

Whether the sender's body credential was in force when it spoke is the Identity
Agent's to check at the time. The entry names the credential, so a verifier can check
it later against the registry's history. The receiving body does not check it.

The body then sends a receipt signed by its key over the message and its entry hash,
so the record proves the machine received it. Only then does it act. A message is
delivered until its receipt arrives, and acted on once. A message that does not check
out is acknowledged and not acted on. If it was an ask, the body sends a failure notice
saying why, so it neither waits in the queue nor leaves the asker waiting. A check that
could not be made at all, because a key log could not be fetched, is not a refusal: the
message is tried again.

**A body's requests are sealed.** `agent-host` carries every request inside the sealed
transport (`didcomm.SendSealed`, the same format an Identity Agent uses to reach a peer).
It seals from the keys the body enrolled with to the Identity Agent's. The message
routes refuse a body-signed request that did not arrive that way.

**The brain is a program the body runs, with the full use of its machine and one
route to the Identity Agent.** The body runs Claude Code or Grok CLI, whichever the AI
agent was created with, as a single non-interactive run per message, in the
conversation's own session. The machine is the AI agent's to use: the brain keeps the
program's own tools and is never stopped to ask. Restricting what a program may do on
its own machine is a contest it eventually wins, and governs nothing the Identity Agent
holds.

What is governed is the Identity Agent's side. The brain reaches the Identity Agent only
as its AI agent, under that AI agent's grant, through the body's tools:
- `reply`, `ask_agent`, `list_agents` and `conversation_history`;
- `system_info`, a fixed set of facts about the machine.

It loads no MCP server but the body's, so it never reaches the Identity Agent through a
connection a person set up with their own token. On a machine a person also uses, the
brain runs as its own operating-system user, so it cannot use that person's keys either.
Grok CLI always runs that way, because it loads the MCP servers of whoever runs it and
has no option to ignore them.

The tools reach the body through a stdio MCP server, holding a token good for one
turn. The token travels in the brain's environment, and the words and instructions
travel on stdin. Neither goes on the command line, which other users of the machine can
read, nor into a file. Since neither program takes a system prompt from stdin, the
instructions lead a session's first message instead. The brain never holds a key. If
the brain fails, the body sends a signed failure notice, so a conversation never waits
on silence.

**Who is asking is whoever started the request, never the machine.** A machine key
proves which body an AI agent spoke from. Approving a machine as a body is recorded,
and grants nothing to later requests: the AI agent's grant decides what it may do, and
the person or AI agent who opened the conversation decides how far it may reach. A
person using a tool on a machine that is also an AI agent's body is still the person
asking, and must sign as themselves.

## Consequences

- A conversation between AI agents is provable from the record alone: who opened it,
  each message's sender and their signature, the Identity Agent's countersignature
  as each AI agent, the chain of entries, and each body's grade.
- A compromised Identity Agent could forge its own countersignatures, but not a body's
  statement made with a key it never held, nor a controller's signature. The sender's
  own signature is therefore the strong evidence of who said what. A compromised
  Identity Agent could still invent a controller grant or issue a body credential to a
  key of its own, and sign as that. Controller grants are not yet anchored anywhere a
  verifier could check.
- A reply sent with the body's `reply` tool names the brain's session but carries no
  digest of the run, because the run has not finished when it is sent. Only an answer
  given by ending the turn carries the digest.
- An employee's own messages are not yet supported. An employee's device is never made
  a controller, because a controller can do nearly everything the owner can. An
  employee will instead sign with their own identity. Until then, only signers start
  conversations.
- A person's own requests are signed but not sealed, so a relay where TLS ends can read
  the question and the answer. The bodies' legs are sealed.
- Anchoring a conversation's head in a key event log is not part of this decision. Until
  it is anchored, deleting the last entries of a conversation is not detectable from
  the record alone.
- Running the brain as a separate Windows user is not available yet. On a Windows
  machine a person also uses, the brain runs as that person's user.
