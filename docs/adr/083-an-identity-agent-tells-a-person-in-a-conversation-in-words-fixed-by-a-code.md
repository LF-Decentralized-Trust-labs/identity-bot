# ADR-083: An Identity Agent Tells a Person Something in a Conversation, in Words Fixed by a Code

**Status:** Proposed (2026-11-15)
**Date:** 2026-11-15
**Deciders:** to be decided; the kind is public wire once this ships, and a checker of a trail refuses an entry of it that breaks the rules below
**Amends:** ADR-068 (a conversation's trail keeps who said what, never the words): the Identity Agent is now also a party that says something, in fixed words that the trail holds as a code
**Builds on:** ADR-077 (a conversation closes by a signed entry from its opener or its owner), for when a conversation is closed

---

## Context

Before something is kept about a person that they do not know of, they should be told, in the place they are talking, by the party who answers for it: the Identity Agent, and not an AI agent whose words could say anything. Today the only entries the Identity Agent writes itself are outcomes, which are about an earlier entry. A notice is not about an earlier entry, and it cannot be an AI agent's entry, so it needs a kind of its own.

The words must not be free text: a notice that could say anything is one more place an AI agent, or a mistake, can put words into the Identity Agent's mouth, and the trail keeps no words (ADR-068).

## Decision

1. A conversation entry of kind **`notice`** is the Identity Agent's own word to a person. It is countersigned like an outcome and carries no sender's proof: the countersignature is the proof.
2. It carries `notice.code`, never text. A code has fixed words, defined once with the contract; every reader shows those words for the code. The first code is `notes-kept-about-you`: "Notes may be kept about you by the AI agents of this organisation. You will be invited to a page where you can see them and delete them."
3. **What a checker refuses.** A notice from anyone but the conversation's Identity Agent; to anyone who is not a person, or to a person who is not in the conversation (neither its opener nor the author of an entry in it that was not refused); naming a code that has no words; replying to a message; carrying a hash of any words; carrying a sender's proof, a refusal, an outcome, or anything the Identity Agent vouches for about a sender as well; carrying any field its contract does not name, or a field spelt in another case; after the conversation has closed and not reopened; and a second notice of one code to one person in one conversation.
4. It takes no turn and acts on no message.

## What stays the Identity Agent's word

That a notice was **delivered** to the person (shown on their screen) is the Identity Agent's and the front end of the person's Identity Agent's, not shown by the record: the trail shows that it was written. Whether something may then be kept (for example, a note about a person after they were told) is the Identity Agent's rule and is not decided here.

## Consequences

- `agentmessage` gains `KindNotice`, `Notice`, the codes and `NoticeWords`; `conversationbundle` checks the rules in 3; `agent-message.schema.json` describes the kind and the `notice` object.
- A reader that knows only the earlier kinds refuses an entry of kind `notice`, as it refuses any kind it does not know.
