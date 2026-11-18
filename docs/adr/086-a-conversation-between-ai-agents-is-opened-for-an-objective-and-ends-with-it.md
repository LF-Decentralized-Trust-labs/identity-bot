# ADR-086: A Conversation Between AI Agents Is Opened for an Objective and Ends With It

**Status:** Proposed (2026-11-18)
**Date:** 2026-11-18
**Deciders:** Rob Andersen
**Amends:** ADR-047 (AI agents talk through the Identity Agent that holds them): its limit of 40 entries per conversation, raisable to 400; ADR-077 (a conversation closes by a signed entry): who may write each entry, and what a close says
**Builds on:** ADR-045 (every asset gets an identity and a grant from one schema template), ADR-047, ADR-057 (the Identity Agent makes each model call), ADR-068 (a conversation's trail keeps who said what, never the words), ADR-077, ADR-085 (an AI agent messages an AI agent of another Identity Agent)

---

## Context

ADR-047 bounds a conversation by a count: at most 40 asks, replies and failure notices, which the opener may raise to 400 (ADR-077). The reason given was that two AI agents must not talk forever on somebody's bill. The number was never measured against anything.

A count is the wrong measure for both things it is meant to stop. A count says nothing about cost, and cannot tell progress from going round in circles.

It also fails silently. An AI agent that coordinates others kept one conversation per worker open for days and reached the limit with each. Its asks were refused, nobody was told, and one worker received no work for two days.

Task protocols for AI agents, such as the Agent2Agent protocol's task lifecycle, bind an exchange to a task whose states end. That is the shape taken here.

**Threat boundary.** The Identity Agent enforces everything below. A body and the model behind it are not trusted. A compromised Identity Agent, and a model provider that misreports its own charges, are out of scope.

## Decision

1. **A conversation is opened for one objective.** The opening entry's words are the objective: the person's first message, or the opening ask of an AI agent (ADR-047 Amendment 3). They must not be empty and never change. Like any message's words, they are kept where the Identity Agent keeps words (ADR-047), and the trail holds only their fingerprint (ADR-068). New work is a new conversation, not another turn in an old one.

2. **One table says who may write what, and when.** The **owner** is the owner of this Identity Agent as ADR-047 and ADR-077 define it, including the holder of a self-owned Identity Agent. The **opener** is the person or AI agent that opened the conversation. A person's entry is their own signed statement from their own front end (ADR-077); a statement from a body, or a request that the Identity Agent sign as the owner, is never a person's entry. No one else writes any entry, and no other rule in this ADR or in ADR-077 grants authority.

   | Entry | Written by | Admitted while | Moves to |
   |---|---|---|---|
   | opening | a person (first message) or an AI agent (opening ask, ADR-047 Amendment 3) | none: it starts the chain | `working` if it is an ask to an AI agent, else `waiting` |
   | ask | as ADR-047 allows; from `working`, only an AI agent that owes an answer, within ADR-047's depth | `waiting`, `working` | `working` |
   | answer, failure notice | the party asked, or the Identity Agent for a call it could not price (decision 3), naming an ask of this conversation; at most one per ask | any state | `waiting` if it was the last outstanding ask of an open, unpaused conversation; otherwise no change |
   | progress note | the party asked | `working` | no change |
   | pause | the Identity Agent, under the pause rule below; the owner or a person opener (reason `manual`) | `waiting`, `working`, `paused` | `paused` |
   | resume | the owner; a person opener | `paused`, when every budget has room (decision 3) | `working` if an ask is outstanding, and the Identity Agent then makes that ask's call; else `waiting` |
   | limit | the owner, by a person's entry | any state | no change |
   | close `completed`, `failed` or `cancelled` | the opener; the owner | `waiting`, `working`, `paused` | that word |
   | adopted | the Identity Agent | any state | no change |

   - An ask refused while paused or closed is not written to the chain. The refusal goes to the governance record (ADR-047), and the asker is told at once, by the Identity Agent, with no model call.
   - **The pause rule.** A budget runs out, and only then, when (a) a count or spend reaches its ceiling, through any entry or charge that counts; (b) the hours deadline passes; (c) the next model call does not fit what remains of spend; or (d) a model call cannot be priced in the ceiling's currency (reason `spend`). The Identity Agent then writes a `pause` naming each newly exhausted budget, but only to an open conversation; if it is already paused, the new pause names each newly exhausted budget. Nothing is written as a pause to a closed conversation: a call that finishes after a close is recorded with its charge and nothing else. An entry is never edited.
   - A second answer or failure notice to the same ask is refused and not recorded.
   - While paused, for any reason, no model call starts.
   - Only a close ends a conversation, and it ends every outstanding ask. An answer or failure notice that arrives after it is recorded, names its ask, changes nothing, and never starts a call. There is no reopen: new work is a new conversation. An AI agent that opened a conversation may close it, but never resume or raise it.
   - A conversation whose objective is met but which nobody closes stays bounded by its hours deadline, which pauses it and tells people. The opener is expected to close it, and the supervisor's stall notice covers an opener that does not.

3. **Each conversation gets one set of budgets, fixed when it opens.** Budgets are stated under `agent.message.open` in the grants of the AI agents this Identity Agent holds that take part: the opener and the one asked. A conversation a person opens takes the budgets of the AI agent it is opened to. For each budget the tighter of the ceilings the grants set holds. `limit` raises the conversation's ceilings, within the maxima below.
   - **Time:** `hours`, from the opening entry by the Identity Agent's own clock. The deadline is the opening entry plus the ceiling, so a `limit` that raises `hours` moves the deadline and gives a time pause room to resume. A clock moved backwards does not move it later. Default 24, at most 720.
   - **Entries:** `entries`. It counts asks, answers, failure notices and progress notes; no other entry counts. An ask that would pass the ceiling is not written; any entry that reaches it pauses the conversation under the pause rule. Default 400, at most 4000.
   - **Spend:** every grant issued after adoption states `spend`, as an amount in one named currency or as `"unbounded"`; a grant that states neither is refused at issue. There is no default and no protocol maximum. The owner may raise a ceiling to any amount, or to `"unbounded"`. If two grants set amounts in different currencies, the conversation is refused at opening. Spend counts every model call this Identity Agent makes for a turn in this conversation (ADR-057), at the provider's charge in its reply. Calls for one conversation run one at a time. Under a set ceiling, the Identity Agent prices each call at the most it can cost before starting it. A call that does not fit what remains is not started and its ask stays outstanding. A call that cannot be priced in the ceiling's currency is not started either: the Identity Agent ends its ask at once with a failure notice saying so, and the conversation pauses under the pause rule (d). Under the pause rule a charge that reaches the ceiling pauses at once, so one call can overrun by its own excess and no more. Under `"unbounded"` no call is priced, refused or paused for.

   **Room**, for `resume`: for time, the deadline is still ahead; for entries, the count is below the ceiling; for spend, something remains, and if a call is waiting from a spend pause, its price fits.

   Budgets are checked when each entry is written, before and after each model call, and by the timer in decision 4.

4. **The Identity Agent watches the clock, not only the entries.** A quiet conversation writes no entry, so a scheduled check, at least once a minute, writes the `pause` when a deadline passes, under the pause rule, and raises the notices of decisions 5 and 6.

5. **A pause is told to people where they already look.** Every `pause` entry writes a `conversation.paused` event to the signed governance record, with the conversation's identifier, its state and its reasons, never words. It goes to the owner and a person opener on the alert surface each already watches, not only inside the conversation's view, and stays until the conversation is resumed or closed. An opening refused for the hourly rate of ADR-047 Amendment 3 writes a `conversation.refused` event, told the same way.

6. **A supervising AI agent sees the structure of its AI agents' conversations, and never the words.** A new capability, `agent.conversation.oversee`, issued only by a person, lists the AI agents its holder supervises: `{"agent.conversation.oversee": {"agents": ["<identifier>", …], "stall_minutes": 60}}`. A list naming any AI agent this Identity Agent does not hold is refused at issue. It grants no entry in the table.
   - **It may read**, for any conversation on this Identity Agent that one of those AI agents is in: the parties, the state, the times, and use against each budget. Never the objective, in words or fingerprint, and never any other words. Every read is a signed governance entry.
   - **It is told**, once when each becomes true and never as a turn in a conversation: a pause; a close that says `failed`; a stall, when an ask to one of those AI agents has had no answer or failure notice for `stall_minutes` (progress notes do not restart it); and a budget passing 80% of its ceiling (not for unbounded spend). A notice carries the conversation's identifier, its state and the reason, never words.
   - **It cannot see** a conversation busy going nowhere in words that look like progress; the budgets bound that.

7. **Depth stays at three.** ADR-047's limit of three asks deep is kept: it bounds how far work is delegated, which no budget measures.

8. **Across Identity Agents, each side applies its own, and says nothing about it.** ADR-085 gives each side its own conversation; each Identity Agent applies this decision to its own side, with its own owner. Pauses, budgets and the word of a close are never sent across. An ask from another Identity Agent into a paused or closed conversation is refused as in decision 2, and the sender gets an ordinary failure notice with no reason (ADR-085 decision 8). On the sender's side it is a failure notice like any other.

## What this amends

1. **ADR-047**, *"A conversation holds at most 40 asks, replies and failure notices. Asks stop there."* The count is now the entries budget of decision 3, and reaching it pauses the conversation and tells people instead of refusing in silence. *"A chain of asks goes at most three deep"* is unchanged. The 30-minute idle close, already removed by ADR-077, is not restored.
2. **ADR-077**, decision 1 and its amendment. Who may write `close` and `limit` is decision 2's table, which replaces ADR-077's rules for them: the opener, AI agent or person, may still close; only the owner may raise a limit; `reopen` is withdrawn, and `limit` is bounded by decision 3 instead of 40 to 400. A new `close` carries `completed`, `failed` or `cancelled`. `pause`, `resume` and `adopted` are added.

## Recorded conversations

A conversation opened after adoption marks its opening entry as made under this decision, and its whole chain follows the table. When an Identity Agent adopts this decision, it records an `adopted` event in its governance record and writes `adopted` into every unmarked chain it can still write to, closed ones included. A checker accepts the earlier forms, a `close` with no word (read as `completed`) a `limit` from an AI agent opener and a `reopen`, only in a chain whose opening entry is unmarked and only for entries before its `adopted` entry. An unmarked chain with no `adopted` entry is accepted as recorded, because a checker cannot tell from the chain alone whether its Identity Agent had adopted this decision; a checker given that event refuses earlier forms written after it. At adoption each open conversation is checked once against its grants, with the deadline from its original opening entry. One at or over any ceiling gets one `pause` naming every such budget, never one per earlier entry, and the chain is not rejected. Long-open conversations, such as those an AI agent that coordinates others keeps with each worker, will pause at adoption: that is the stuck work this decision exists to surface. The owner gets one notice listing every conversation paused at adoption, and each person opener one listing theirs. A grant issued before adoption that states no spend is read as `"unbounded"`, and the owner's notice says so.

## Consequences

- `agentmessage` gains `KindPause`, `KindResume` and `KindAdopted`, the three words of a close, the opening entry's mark, the budget fields of `agent.message.open`, and `agent.conversation.oversee`. `conversationbundle` checks decision 2's table and the cut-over. The vectors and both independent checkers carry them.
- What a checker cannot see stays the Identity Agent's word: the time it measured, the price and charge it saw, and that a notice was shown. Whether a pause's reason was true is not provable from a bundle.

## Alternatives rejected

- **A bigger fixed count.** No one number fits every task, model and cost.
- **Opening a new linked conversation when the count is reached.** It keeps the wrong bound and hides the stall from the person.
- **Pausing on repeated asks.** The trail keeps no words (ADR-068), so it would need new storage; budgets already bound a loop.
- **Giving the supervising AI agent the words.** Untrusted words in its model could steer the one AI agent meant to catch problems.
- **Holding an ask from another Identity Agent while paused.** A hold queue adds state for little gain.
