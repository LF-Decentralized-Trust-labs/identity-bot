# ADR-081: An AI Agent May Add to an Answer It Has Given, With an Addendum That Owes No Answer

**Status:** Proposed (2026-11-15)
**Date:** 2026-11-15
**Deciders:** to be decided; the kind below becomes public wire once this ships, and third parties then check it
**Builds on:** ADR-047 (AI agents talk through the Identity Agent that holds them), ADR-068 (a conversation's trail keeps who said what, never the words), ADR-077 (a conversation closes only by a signed entry)

---

## Context

An AI agent that has answered may find it has more to say: a result that arrived later, a correction, a pointer. Today it has two ways to say it, and neither works for everyone it may have answered.

- A new ask reaches only an AI agent. An ask is never addressed to a person, and it would owe an answer the asker may not give.
- A progress note is only for an ask still being worked; one after the answer fails the published checker (`conversationbundle/verify.go`).

So an AI agent that answered a person has no way to add to the answer.

## Decision

1. **A new entry kind, `addendum`.** It says "more to say about what I answered; no answer is owed". It is written by the one who answered an ask, to the one who asked it, in the conversation the ask was in. `in_reply_to` names the ask that was answered. Its words are the addition. The one who asked may be an AI agent or a person.
2. **What a checker verifies.** The addendum is from the one the ask was put to and to the one who sent it; it names an earlier ask of this conversation; that ask was answered by a reply (not a failure, which says nothing was given to add to); and the conversation is not closed at that point. Any number may follow one answer. It does not answer, close or reopen anything, and nothing answers it: no reply, failure or progress note may name one in `in_reply_to`. A receipt may acknowledge it, and the one it goes to may act on it as on any message given to them, by asking something new.
3. **No turn.** An addendum takes no turn against the conversation's limit, as a progress note does not, and the one it goes to owes no reply. It reopens no ask: the ask stays answered.
4. **Who signs.** An AI agent's body signs it as it signs a progress note: a statement of kind `addendum` over the words, from the answering AI agent, to the asker, acting on the ask. When the asker is a person the entry is addressed to `person:` followed by their identifier, as a reply to a person is.
5. **Which answered ask.** The addendum names the ask it adds to. An AI agent that answered several askers in one conversation says which by naming that ask, and the recipient follows from it. Nothing else decides the recipient.
6. **A person's screen shows it** as a later line of the answer it adds to, in the Identity Agent app or in a utility app's installed front end; that is that front end's choice and not checked.

## What stays the Identity Agent's word

Whether the one who wrote it is the one the ask was put to is shown by the chain, so it is checked. That a front end showed it, or a person read it, is not shown by the record.

## Consequences

- `agentmessage` gains `KindAddendum`; `conversationbundle` checks the rules in 2.
- `message-vectors.json`, the schema and the independent Python checker carry the new kind. A reader that knows only the earlier kinds refuses a statement of it, as it refuses any kind it does not know.
- An add-on that carries an AI agent's follow-ups uses it for a follow-up to a person, and lets the AI agent name which answered ask. How long that add-on keeps answered asks to follow up on is its own choice and not wire.
