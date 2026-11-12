# ADR-077: A Conversation Closes by a Signed Entry From Its Opener or Its Owner, and Never for Being Quiet

**Status:** Proposed (2026-11-12)
**Date:** 2026-11-12
**Deciders:** to be decided; the kinds below become public wire once this ships, and third parties then check them
**Amends:** ADR-047 (it no longer says a conversation closes after 30 minutes with nothing said, or at a hard limit with an ask unanswered; a progress note no longer restarts an idle clock)
**Builds on:** ADR-047 (AI agents talk through the Identity Agent that holds them, including Amendment 3), ADR-067 (a person signs a salted fingerprint of their words), ADR-068 (a conversation's trail keeps who said what, never the words)

---

## Context

A conversation used to end by the clock: open for a while after its last entry, shut after that. Three weeks waiting on a person was therefore a closed conversation, and the end of one left no mark in the signed trail: nobody checking a trail could tell a conversation that ended from one that went quiet.

## Decision

1. **A conversation is closed only by an entry in its chain.** Nothing closes one for being quiet. Three entry kinds are added beside ask, reply, receipt, failure and progress:
   - `close`: the one who opened the conversation says the work is done. The organisation's owner may also close any conversation, by their own signed statement; the entry names the owner, so a trail shows an owner overriding the opener.
   - `reopen`: the opener undoes a close. Only the opener does.
   - `limit`: the opener raises the number of turns the conversation may hold. The words are the new limit in decimal digits; it is above 40 and no higher than 400.
2. **Who signs.** An AI agent opener signs as its body signs an ask: a statement of kind `close`, `reopen` or `limit` that addresses nobody (`to` empty) and acts on no message (`in_reply_to` empty). A person signs a statement of kind `close`, `reopen` or `limit` (`limit` is new in `signed-fingerprint.md`), with no recipient. Each is countersigned and chained like any entry.
   An app carries a person's statement of these kinds on `POST /api/mcp/conversations/{cid}/close`, `/reopen` and `/limit`, as it carries their words on the talk route: the core admits it only for the kind the route is for, over that conversation, to nobody, with no words (a limit's words are the new limit).
3. **What a checker verifies.** A close is by the opener or by an owner's statement (standing `owner`); a reopen and a limit are by the opener; a close needs the conversation open and a reopen needs it closed; a close and a reopen carry no words; a limit's words parse and are within the bounds above; and no ask is recorded while the conversation is closed. An answer to an ask made before the close is kept after it and does not reopen the conversation.
4. **Asks left unanswered end.** When a close finds an ask still unanswered, the Identity Agent writes an `outcome` entry of state `closed-unanswered` for it, addressed to the AI agent that owed the answer, once per ask, after the close. A checker refuses one for an ask that was answered, one before any close, and a second for the same ask. An answer that still comes is kept, and the conversation stays closed.
5. **An ask whose body was lost ends too.** When the body holding an unanswered ask is lost, revoked or archived, nothing will answer it. The Identity Agent writes an `outcome` of state `body-lost`, with a reason, addressed to the one who asked, once per ask, in a conversation still open (after a close, `closed-unanswered` already ends it). That the body was lost is the Identity Agent's word, and a checker says so.
6. **No turn.** These entries take no turn and no message id of their own beyond the chain's.

## What stays the Identity Agent's word

That the owner's statement is from someone with standing `owner`, and whether a limit raise took the running limit up (the checker does not count turns), are the Identity Agent's, not shown by the record.

## Consequences

- `agentmessage` gains `KindClose`, `KindReopen`, `KindLimit`, `PersonKindLimit`, the limit bounds and `ParseTurnLimit`; `conversationbundle` checks the rules in 3.
- The published vectors (`message-vectors.json`, `signed-fingerprint-vectors.json`), the schema and both independent checkers carry the new kinds.
- A reader that knows only the earlier kinds refuses a statement of a new kind, as it refuses any kind it does not know.
