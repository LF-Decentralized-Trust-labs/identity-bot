<!-- Title: imperative, under ~70 characters, stating the outcome and not the mechanism.
     Good: "Open the enrolment route at the path it is actually mounted at"
     Weak: "fix: routing bug"
     Someone scanning a list of pull requests should be able to tell from the title
     and the Summary below whether this one concerns them.

     The comments in this template disappear when the page renders — write your text
     underneath each heading, and delete any optional line you do not use.

     LENGTH. The whole body should be readable in about a minute. Reviewers read
     the diff; this page exists to tell them what to look at and why, not to
     re-explain the change in prose.

     THE TEST FOR EVERY SENTENCE: would a reviewer be worse off if it were
     deleted? If not, delete it. Background they already have, reasoning that
     does not change what they check, and anything restating the diff are all
     filler, and filler is not harmless — it buries the two or three sentences
     that actually matter and teaches people to skim the whole page. -->

## Summary

<!-- One sentence that expands the title by a single notch: the title says the
     outcome, this says the same thing with just enough substance that somebody can
     tell whether it concerns them. State what the change does, in the present
     tense, as a fact about the software once this merges.

         <What the change now does.>

     Plain text. A second sentence only when one cannot carry it; never a third.

     Do not write a before-and-after. "It used to do X, now it does Y" is two facts
     where one is wanted, and it spends the first half of the sentence on code that
     is about to stop existing. What was wrong belongs under Why.

     A summary that names only the problem is the other mistake, and a worse one:
     the reader cannot tell whether this PR causes that problem, fixes it, or merely
     describes it. The test: could this sentence be the title, if the title had room?
     If it reads like the opening of Why, it is the wrong shape. -->

## What This Is

<!-- One or two plain sentences: what this pull request changes. Don't restate the
     title. Write it so a developer who has never seen this subsystem understands it
     on one read — no jargon, no assumed context. -->

## Why

<!-- One or two plain sentences on why this is worth doing — what it makes
     possible, or what it costs to leave alone. This is where what was wrong goes,
     since the Summary states only what the change does. Don't repeat the Summary. -->

## Affected

<!-- Where this lands. One line each; delete any line that does not apply.

     - Subsystem — the named runtime part, with its package: the credential vault
       (`CredentialVault`, `identity-agent-core/vault`), the forward proxy, the
       attestation runner, the KERI driver.
     - User-facing — what a person using an app built on this core would notice,
       or "none". The core ships no screens, so say where the change is *felt*.
     - Developer-facing — the exported symbols, HTTP routes or SDK surface a caller
       would notice, and say plainly what stays unchanged.

     Reviewers triage on this. Trace it rather than guessing: a fix at a shared
     chokepoint reaches every caller of it, and that is usually wider than the
     directory the diff sits in. -->

## Who This Helps

<!-- ONE OR TWO SENTENCES. Who outside this project can use this, and what it gives
     them. Longer only where the change genuinely establishes something complicated,
     which is rare.

     This project is an open, vendor-neutral reference implementation of the Identity
     Agent Protocol, so a change has to earn its place for people who are not you.
     A narrow use case is fine when the mechanism is general — say which it is.
     If the only honest answer is one vendor's private interest, that is a sign the
     change belongs in a project built on top of this one.

     Do not list every party it might conceivably help, and do not restate the
     mechanism here — that is What This Is. -->

## Testing

<!-- What you ran and what you saw. For a change in behaviour, name the case that
     would have failed before. "The tests pass" on its own is not evidence.
     Say plainly what you did not test, and why.

     DO NOT REPORT A KNOWN FAILURE THAT IS NOT YOURS. A pre-existing red test
     does not belong in the Testing section of an unrelated change. Repeating it
     on every pull request teaches the reader that this project always has
     failures, and buries the one line saying what this change proves. Fix it,
     or log it once and say nothing further.

     COUNTS ARE NOT EVIDENCE. "28 of 29 packages pass" is the same sentence on
     every pull request and reads as a standing fault. Name the case that would
     have failed before, and what you did not test. Nothing else earns a line. -->

<!-- Optional, one line each, no heading. Delete the ones that don't apply.

     Fixes #123
     Risk: what breaks if this is wrong, and how to revert it.
     Release note: one line for the release changelog.

     Anything else — design notes, trade-offs, guidance for the reviewer — goes
     after these headings under its own, and only when a reviewer would otherwise
     miss something. It is not a routine section.

     SAY THE GENERAL THING, NOT THE PRIVATE ONE. This is the open, vendor-neutral
     core. Explaining how organisations work, or what any product built on this
     needs, is filler here. Mention an organisation only where it is the shortest
     way to state a general rule, never to explain the organisation itself.

     NEVER REVIEW YOUR OWN PULL REQUEST INSIDE IT. No commentary on the review
     process, no notes to whoever merges it, no grading your own work.

     Every commit needs a DCO sign-off line — `git commit -s` adds it:
     Signed-off-by: Your Name <you@example.com>
     Angle brackets are required, or the DCO check fails. -->
