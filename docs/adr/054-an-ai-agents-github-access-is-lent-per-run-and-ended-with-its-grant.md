# ADR-054 — An AI agent's GitHub access is lent per run, and ended with its grant

**Status:** Accepted
**Date:** 2026-10-26
**Relates to:** ADR-045 (Every asset gets an identity and a grant from one schema template), ADR-046 (A machine becomes an AI agent's body by a person comparing six words), ADR-050 (One check for a controller's actions and an AI agent's capability calls), ADR-051 (An AI agent's brain is signed in once, and lent to a body per run), ADR-052 (A brain's sign-in is checked before it is kept, and capped per account)

## Context

An AI agent that writes code needs a repository. Until now the only way to give it
one was to put a credential on the machine it runs on: a deploy key, or a person's
token. Either is a copy nobody governs. A deploy key is permanent and belongs to one
repository. A personal token is a person's whole account. Neither ends when the AI
agent is revoked, neither records which runs used it, and replacing either means
somebody going to every machine.

ADR-051 settled how a brain's sign-in reaches a body: kept in the Identity Agent's
vault, lent sealed for one run, given back when the run ends. A service credential
has the same problem and wants the same answer, with one thing more. A brain's
sign-in is long-lived and has to be. A service that can issue short credentials of its
own lets the Identity Agent lend something that expires by itself and can be
withdrawn early.

## Decision

**The rule for every service credential.** Choose the credential the Identity Agent
can renew by itself, so no person rotates anything. Tie every use to the AI agent's
grant, so revoking the AI agent, or its grant for that service, ends its access. Lend
only short credentials the Identity Agent can withdraw, and withdraw them at once
when the grant no longer covers them, rather than waiting for them to lapse. Where a
service offers no short credential, the vault lends the long one per run, as it does a
brain's key.

**GitHub access is a capability grant.** Two capabilities, in the `github` pack:

- `code.repository.read` — clone and read;
- `code.repository.write` — also commit, push and open pull requests.

Each is lent, never invoked, so its executor type is `lent_credential`, which the
gateway reserves and does not offer as a tool. A grant of either names its
repositories in its resource constraints, as `repository`: a list of `owner/name`,
and as `repository_id`: GitHub's number for each, in the same place. The number is
what is granted. A repository deleted and made again under the same name has another
number, so it is not covered, and a name with no number gives nothing. A grant that
names none gives none. Write includes read, so a repository it may write is named
under read as well: a run refused write by the one check still reads it. The
repositories an AI agent may use are set in one call, which looks each one's number
up through the App's installation, re-issues its grant and keeps its other
capabilities and limits as they are. A repository the organisation's GitHub App cannot
reach is refused. Every repository the App reaches is listed, however many there are.

**The organisation connects a GitHub App once.** A person creates the App and installs
it on the repositories the organisation lets AI agents use; GitHub asks them to
approve that. Its App ID, installation ID and private key are then sent to the
Identity Agent, which first asks GitHub, with the key, what the App and its
installation are. A wrong key or number is reported then, and nothing is kept.
Otherwise the three are kept in the vault, with the App's name, its bot account and
the account it is installed on. The private key is never returned by any route, never
logged, and never leaves the vault: it is used only to sign the short statement
(RS256, valid nine minutes) with which the Identity Agent asks GitHub for a token.

Replacing the App — another App, another installation, or the same one with a new
key — withdraws everything lent under the one it replaces. Each lend records the App,
installation and key that made it, so a lend made under one that is no longer
connected is withdrawn too.

Connecting, replacing and disconnecting the App, listing the repositories it reaches,
and granting an AI agent repositories are the application's work: open to the owner
and to an authorised controller (ADR-050), and closed to a browser session. A
session's change would outlive it, and the key makes tokens for the organisation's
repositories.

GitHub's address is fixed. Nothing a request sends can change where the Identity
Agent sends the App's statement or a token. Every request to GitHub goes out the
Identity Agent's own governed way, with its policy check — including any domain the
owner blocked — proxy log and trace. The vault adds no key of its own to it, and no
redirect is followed.

**A body is lent GitHub access per run.** When a run starts, the body asks for it,
signed by its machine key and sealed to the Identity Agent (ADR-046). The Identity
Agent:

1. refuses an AI agent whose grant is revoked or lapsed, or that may do nothing now;
2. runs the one check (ADR-050) for each capability it would lend: the capability is
   offered as a lent credential and enabled, the AI agent's grant gives it, and the
   AI agent passes its minimum score;
3. asks GitHub for installation tokens limited to exactly the repositories the grant
   gives, by GitHub's numbers for them (`repository_ids`), each with exactly one
   access's permissions — `contents: write`, `pull_requests: write` and
   `metadata: read` for write; `contents: read` and `metadata: read` for read. One
   token has one set of permissions for all its repositories, so a grant that writes
   any repository is two tokens: one that writes those it may write, and one that
   reads every repository it may use. The read token is made even when it may write
   every one, so turning write into read withdraws only the write token and the run
   keeps reading. The `workflows` permission is never asked for;
4. checks GitHub's answer is no wider than it asked — a selection, not every
   repository; at least one repository, and only those asked for, by number; and
   exactly the permissions asked — and withdraws a token that is not;
5. records the lend in the vault, in the one record of everything it lends (with
   brains' sign-ins), with its tokens, so it can withdraw them early, and the App,
   installation and key that made them;
6. checks the lend again now it is recorded, so a grant, body or App that changed
   while GitHub was making the tokens is withdrawn, not handed over. A lend that
   cannot be checked — what is lent, or the App, cannot be read — is withdrawn and
   refused too;
7. writes the lend to the signed governance record as the AI agent, naming the body,
   the repositories and the access, never a token;
8. answers sealed to the keys the body enrolled with.

A body holds one GitHub lend at a time. Borrowing again withdraws what it held, and a
body that starts again gives back whatever it held before, so nothing from a run it
stopped in stays lent until it lapses.

A body may name fewer repositories than its grant gives. One its grant does not give
is refused. An AI agent with no repositories is told so, and runs as before.

GitHub makes each token last an hour at most. A run is shorter, so a token is never
renewed.

**The body gives it to the brain's environment, and nowhere else.** `GH_TOKEN` carries
one token for `gh`: the write token when the AI agent may write every repository it
uses, otherwise the token that reads all of them. git is pointed, through
`GIT_CONFIG_*` variables, at the body's own program as its credential helper. The
helper reads the tokens from the environment and answers git with the write token for
a repository the AI agent may write, the read token for one it may only read, and
nothing for any other. Every credential helper configured before is set aside for the
run, and every GitHub token or git setting in the machine's own environment is
withheld, so neither program falls back on access somebody set up by hand. An SSH
address on GitHub (`git@github.com:` or `ssh://git@github.com/`) is rewritten to
HTTPS, for fetching and pushing, so it uses what was lent rather than a key in
`~/.ssh`. Nothing is written to disk, and no token goes on a command line. A brain run
as its own user is started through sudo, and none of it passes through sudo: it goes on
the standard input of `agent-host brain-env`, which sudo starts as the brain's user and
which puts it in the brain's environment.

*Changed 2026-10-28:* the tokens were passed through sudo's `--preserve-env`, which the
sudoers rule allowed (`SETENV`). sudo writes the value of every variable it passes on to
the system log, so a lent token, and a lent brain sign-in with it, outlived its lend
there. They now travel on standard input instead, which sudo does not log while input
logging is off, and the sudoers rule keeps it off for `agent-host` itself. A machine set
up before this change keeps the old rule and leaks the same way until its `agent-host`
and its sudoers rule are replaced together; either one alone stops the brain from
starting, since each refuses what the other expects.

The brain holds the tokens in its environment for the run. It can read them, and could
put them in what it writes — its output, a file, a commit. What it could leak is
short-lived and narrow: each token works only for the repositories lent, for an hour at
most, and is withdrawn at GitHub when the run gives it back.

Commits name the AI agent as their author and committer, at the address of the App's
bot account, so GitHub shows them as the App's and each names the AI agent.

**The access ends with the run, and with the grant.** When the run ends, or fails, the
body returns the lend and the Identity Agent withdraws its tokens at GitHub
(`DELETE /installation/token`). Every lend whose AI agent's grant no longer covers it
is withdrawn the same way, at once:

- when any credential is revoked or withdrawn — the AI agent's grant, or a body's;
- when an AI agent's grant is re-issued, so taking a repository away, or turning write
  into read, withdraws the tokens that gave it — only those: turning write into read
  withdraws the write token, and the run keeps the token that reads;
- when a machine is removed as an AI agent's body;
- when the App is disconnected or replaced, including a new key for the same App,
  which withdraws them all;
- when the body borrows again, or starts again;
- and every minute, which covers a grant that lapses by time.

A sweep that cannot read the organisation's GitHub App connection ends every GitHub
lend: what cannot be checked is not left lent.

A withdrawal GitHub cannot be reached for is tried again, each minute, until the token
would have lapsed. A token that has lapsed is let go.

## Consequences

- No person rotates a GitHub credential. The App's key needs no routine rotation: it
  never leaves the vault, and replacing it is connecting the App again.
- Revoking an AI agent ends its GitHub access within the time it takes to reach
  GitHub, not within the hour.
- A body holds a token only while a run uses it. A compromised body could use or copy
  what it holds during that run, for as long as the token lasts or until it is
  withdrawn, whichever comes first: an hour at most.
- `gh` is given one token. An AI agent that may write to some repositories and only
  read others is given the one that reads them all, so `gh` reads every repository it
  may use but cannot push or open a pull request; git pushes with the write token, and
  a brain opens a pull request with `gh` by giving it `AGENT_HOST_GITHUB_WRITE_TOKEN`
  for that command.
- git's own way to GitHub is the token lent. A key in `~/.ssh` still works for a host
  name that is not `github.com` — an alias in `~/.ssh/config` — and a person's own
  `pushInsteadOf` rule that sends an HTTPS address over SSH still applies. A body
  lent GitHub access should hold no GitHub key of its own.
- Commits appear on GitHub as the App's, not a person's. The author line names the AI
  agent, and the governance record says which AI agent was lent which repository,
  when, and on which machine.
- The organisation creates its GitHub App on GitHub's own site; the Identity Agent
  cannot create one or its key. The App needs the permissions above at least.
- An AI agent cannot change a file in `.github/workflows`. GitHub refuses a push that
  does without the `workflows` permission, which is deliberately not asked for: a
  workflow runs with the repository's own secrets, so changing one is more than
  changing code.
- A brain's sign-in and a service's access are lent by two routes into one record of
  everything lent, kept in the vault. They share the checks that decide whether
  anything may be lent, the way a lend is held, given back, lapsed and recorded, and the
  one sweep that ends what a grant no longer covers. What is lent, and how it is
  withdrawn, differs by service. So revoking an AI agent ends its brain's lease at once
  too: the lease holds no place and cannot be renewed, though the run keeps the sign-in
  it was given until it ends (ADR-051), and can still give back one its program
  refreshed. Leases an earlier version kept in a file of their own are moved into the
  record when the vault can take them.
- Not yet proven against GitHub itself: the tests use a stand-in that checks the App's
  signature and records the tokens made and withdrawn.
