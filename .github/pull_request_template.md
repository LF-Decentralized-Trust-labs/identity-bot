<!-- Title: imperative, under ~70 characters, stating the outcome and not the mechanism.
     Good: "Open the enrolment route at the path it is actually mounted at"
     Weak: "fix: routing bug"
     Someone scanning a list of pull requests should be able to tell from the title
     and the Summary below whether this one concerns them.

     The comments in this template disappear when the page renders — write your text
     underneath each heading, and delete any optional line you do not use. -->

## Summary

<!-- One sentence: what this does and why it matters, for someone who reads nothing
     else on this page. Carry the consequence; don't just restate the title.

     This is the change at a glance. The section below is the detail. -->

## What This Is

<!-- One or two plain sentences: what this pull request changes. Don't restate the
     title. Write it so a developer who has never seen this subsystem understands it
     on one read — no jargon, no assumed context. -->

## Affected

<!-- Where this lands. One line each; delete any line that does not apply.

     - Subsystem — the named runtime part, with its package: the credential vault
       (`CredentialVault`, `identity-agent-core/sandbox`), the forward proxy, the
       attestation runner, the KERI driver.
     - User-facing — the navigation items in docs/adr/018-desktop-navigation-structure.md
       (Credentials → API Keys, Apps → Marketplace, Settings → Security, History …),
       or "none" when no screen changes. Say where the change is *felt*, not only
       where a screen changed.
     - Developer-facing — the exported symbols, HTTP routes or SDK surface a caller
       would notice, and say plainly what stays unchanged.

     Reviewers triage on this. Trace it rather than guessing: a fix at a shared
     chokepoint reaches every caller of it, and that is usually wider than the
     directory the diff sits in. -->

## Why

<!-- One or two plain sentences: what was wrong, or what this makes possible. -->

## Who This Helps

<!-- This project is an open, vendor-neutral reference implementation of the Identity
     Agent Protocol, so a change has to earn its place for people who are not you.

     Name who outside your own use of the project can use this, and what general thing
     it establishes for them — a framework, a seam, an interoperability decision, a
     schema, a contract others build against.

     A narrow use case is fine when the mechanism is general: say plainly which it is.
     If the only honest answer is one vendor's or one deployment's private interest,
     that is a sign the change belongs in a project built on top of this one. -->

## Testing

<!-- What you ran and what you saw. For a change in behaviour, name the case that
     would have failed before. "The tests pass" on its own is not evidence.
     Say plainly what you did not test, and why. -->

<!-- Optional, one line each, no heading. Delete the ones that don't apply.

     Fixes #123
     Risk: what breaks if this is wrong, and how to revert it.
     Release note: one line for the release changelog.

     Every commit needs a DCO sign-off line — `git commit -s` adds it:
     Signed-off-by: Your Name <you@example.com>
     Angle brackets are required, or the DCO check fails. -->
