# ADR-077: A Conversation Closes by a Signed Entry From Its Opener or Its Owner, and Never for Being Quiet

**Status:** Proposed (2026-11-12)
**Date:** 2026-11-12
**Deciders:** to be decided; the kinds below become public wire once this ships, and third parties then check them
**Amends:** ADR-047 (it no longer says a conversation closes after 30 minutes with nothing said, or at a hard limit with an ask unanswered; a progress note no longer restarts an idle clock)
**Builds on:** ADR-047 (AI agents talk through the Identity Agent that holds them, including Amendment 3), ADR-067 (a person signs a salted fingerprint of their words), ADR-068 (a conversation's trail keeps who said what, never the words)
**Amended:** 2026-11-18 — Who may write close and limit is ADR-086's table: the opener may still close, only the owner raises a limit, and reopen is withdrawn (new work is a new conversation); a close says completed, failed or cancelled, and pause, resume and adopted are added (see ADR-086)

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

## Amendment (2026-11-14): the holder of a self-owned Identity Agent is its owner, and a person who stands

**Why.** The decisions above name the owner as someone other than the Identity Agent: the one its own inception event names, or the one sealed at provisioning. An Identity Agent on a person's own device names neither; its owner authority is its own identity (`ownerAuthority`'s last resort), so no one passed "standing `owner`" and nobody could close a conversation an AI agent of a contact had opened (ADR-080).

**Decision.**
1. An Identity Agent is **self-owned** when its owner authority is its own identity: no owner named in its inception event, none sealed, and no active signer on a roster. Its **holder** is that identity, and stands as `owner` for as long as it is self-owned. An Identity Agent with an owner of its own, or with a signer, is never self-owned, so the identity itself is never a person there.
2. The holder signs a person's statement of kind `close`, `reopen` or `limit` with the identity's current key, the statement's `from` the identity's identifier and its `signer` the non-transferable identifier of that key. The request that carries it must also be the owner's: signed as the owner and admitted by the gate, or made by the owner's own app on this computer (the local owner secret). It goes only to the `/close`, `/reopen` and `/limit` routes: the holder's key does not sign words to an AI agent by this means.
3. The entry records the holder as a person of standing `owner`, so the check in decision 3 above (a close by the opener or by a person of standing `owner`) is met with nothing new for a checker to learn. That the key is the identity's current key is the Identity Agent's word, as the owner's standing is.

**Not decided here.** How a front end offers the close, reopen and limit to the holder is the front end's own work; the routes and the signed statement above are what it builds on. ADR-080 decision 9 says a conversation another Identity Agent's AI agent opened stays open on a self-owned Identity Agent until this decision gives the holder a way to close it; this amendment is that way.

