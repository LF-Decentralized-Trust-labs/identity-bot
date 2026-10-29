# ADR-052 — A brain's sign-in is checked before it is kept, and capped per account

**Status:** Accepted
**Date:** 2026-10-26
**Amends:** ADR-051 (An AI agent's brain is signed in once, and lent to a body per run): the cap counts an account rather than one AI agent's sign-in and is one number for it, a Grok subscription runs one at a time by default as Codex does, and the brains a body can run from a lent sign-in now include Codex, a Grok subscription, OpenAI and OpenRouter keys, and servers that speak OpenAI's format
**Amended by:** ADR-057 (An API key stays with the Identity Agent, which makes each model call), 2026-10-28: an API key is no longer lent to a body, so no program on a body is given one
**Relates to:** ADR-047 (AI agents talk through the Identity Agent that holds them), ADR-050 (One check for a controller's actions and an AI agent's capability calls)

## Context

ADR-051 kept an AI agent's sign-in in the vault and lent it to a body for one run.
It left four things open.

- **The cap counted one AI agent.** A subscription is one person's. Ten AI agents
  signed in to one plan, each with a cap of five, could hold fifty runs at once.
- **Several brains could be kept but not run.** Codex keeps its sign-in in a
  file. So does Grok on a subscription. OpenAI and OpenRouter keys had no program
  set up to run them.
- **A sign-in was never tried.** A wrong key showed up at the first run, as a
  failure notice in a conversation.
- **A subscription needed a terminal.** Somebody had to run the provider's sign-in
  command and paste its result into a screen.

## Decision

**The cap counts the account.** Every sign-in of one account shares one count of
runs, whichever AI agents hold it, and one cap: the number is kept for the account,
not for each AI agent, so whichever of its AI agents the owner sets it on sets it for
all of them. A sign-in joining an account takes the cap the account has. The account
is identified in one of two ways.

- **By the account the sign-in names.** A Codex sign-in names its ChatGPT account.
  A Grok sign-in names its xAI user. Two sign-ins made separately for one of these
  accounts are therefore the same account.
- **Otherwise, by a fingerprint of the sign-in itself.** A Claude subscription's
  token and an API key name nothing the Identity Agent can read without using
  them. The same token is the same account.

Two Claude tokens made separately for one account are two fingerprints. The
Identity Agent cannot tell they are one account without using the tokens, and it
must not use them (below). So a front end offers to reuse a sign-in another AI agent
already has, rather than making another. A reused sign-in is copied inside the
Identity Agent, and its secret is never sent back.

A model server with no key names no account and has no secret to fingerprint, so
each AI agent's sign-in to it counts on its own. A lease records the account it
counts against. A lease from before this decision counts against its AI agent alone.

**The default caps.** A Claude subscription runs 5 at a time. A sign-in that renews
itself while it runs — Codex's, and Grok's on a subscription — runs 1 at a time by
default, because two runs renewing one sign-in may sign each other out. The owner may
change either; a front end warns, before raising a self-renewing sign-in past one,
that runs may sign each other out. A subscription is always capped. No cap (0) is
allowed only for an API key or a model server.

**A sign-in can be checked before it is kept.** The check makes one request, to
the provider's cheapest question that needs the key. That is which models the key
may use, or what the key itself is. No model is run and no words leave. The answer
says whether the provider accepted it and, where the provider says, which account
or key name it is. Nothing is kept by checking.

The request goes out the way the Identity Agent's own model calls do, with the
same policy check, proxy log and trace. It differs in two ways:

- the vault adds no key of its own to it, so a key not yet kept is not answered
  with one that is;
- it follows no redirect, so the key goes only to the address it is checked at.

The owner's blocks on where this Identity Agent may go apply to a check, as they now
do to every request the Identity Agent makes for itself.

A model server's address is the caller's, so it is held to more:

- It is asked one fixed question, which models it has, at its scheme and host. Any
  path, query or fragment the address carries is not used. An address carrying a user
  name or password is refused.
- Its name is looked up once, and every address it has is checked. The request goes
  only to an address that was checked, so a name that answers differently a moment
  later reaches nowhere else.
- It is never tried on the Identity Agent's own computer, at a link-local or cloud
  metadata address, or at an unspecified, multicast or reserved one. A model server on
  a private network, such as an office's, is an ordinary place to run one, so a
  private address is tried. Only the owner's own app may ask for a check; a browser
  session may not.
- The answer is whether it worked, and a fixed reason. Nothing the server answered —
  not its status, not its words — is passed back.

A user name or password in any address is left out of the proxy log, the trace and
the governance record.

A kept sign-in can be checked again later. That check is recorded.

**Two kinds of sign-in are never sent anywhere by the Identity Agent.**

- **A Claude subscription's token is for Claude Code alone.** Anthropic does not
  allow anyone else to use a Claude.ai token, so the Identity Agent never uses it
  itself. Claude Code checks it, on the computer that signed it in.
- **A Codex or Grok sign-in is the file the program wrote when the person signed
  in.** That sign-in is proof it worked at that moment. The Identity Agent reads
  the file for its account and checks it is one, but does not use it. A Grok file
  holding tokens for more than one account is refused, rather than one picked from
  it.

**A front end signs a subscription in without a terminal.** It runs the provider's
own program on the person's computer: `claude setup-token` for Claude, `codex login`
for Codex and `grok login --device-auth` for Grok, each in a temporary home of its own
that is deleted when the sign-in ends, and swept the next time the app starts if the
app was stopped first. It reads the token or the sign-in file the program produced,
and nothing else. A Claude token is kept only once Claude Code on that computer has
accepted it.

**A front end lists the brains a body can run.** It offers only those:

| Brain | Program a body runs |
|---|---|
| A Claude subscription | Claude Code |
| An Anthropic key | Claude Code |
| A server that speaks Claude's format | Claude Code |
| A ChatGPT plan (Codex) | Codex |
| An OpenAI key | Codex |
| An xAI key or Grok plan | Grok |
| An OpenRouter key | ~~Grok~~ agent-host's own loop (*amended by ADR-058*) |
| A server that speaks OpenAI's format | Grok |

A Google key is still kept if sent, but is not offered: no program a body runs
takes it yet.

**A program that keeps its sign-in in a file is given the file for one run.**
Codex and Grok each get a home of the body's making, one per AI agent and program,
under the home directory of the user the brain runs as, which only that user can
open. Their sessions stay there, so a conversation can carry on in the next run. The
home holds no sign-in between runs. A sign-in file left in the single home every AI
agent shared before this is removed.

- **A small wrapper writes the sign-in.** It runs as the brain's user, writes the
  sign-in file into that home, runs the program and reads the file back. Then it
  removes the file. It removes it the same way when the run fails or is stopped.
  Before a run, it also removes a sign-in file a crashed run left behind.
- **The wrapper reports on its standard output alone.** Its error output becomes a
  failure notice, so the sign-in never goes there.
- **The program's own settings and sign-in are not read.** A key reaches the
  program as an environment variable. *Amended by ADR-057:* an API key no longer
  reaches the program at all; the variable holds a token for the run, and the
  program's model address is its body's.
- **A model at a sign-in's own address is described in the program's settings for
  the run.** That covers OpenRouter and servers that speak OpenAI's format. The
  settings name the variable that holds the key, never the key.
- **Codex is told about the body's tools on its command line.** The command line
  names the variables that hold the tool address and token, never their values.

**A sign-in a program renewed during a run is kept.** Codex and Grok renew their
own tokens while they run. The token they were lent may stop working once they
have. So the renewed file goes back with the lease, sealed like everything a body
sends. The Identity Agent keeps it, but only:

- while the borrowing AI agent's sign-in is still the one that was lent;
- when the renewed file names the same account and the same person as the one lent
  (for Codex, the account and the subject of its identity token; for Grok, its
  user), and the one lent names an account.

It is written to the borrowing AI agent's sign-in, and to every other AI agent's that
holds the very sign-in lent — one shared from it, which is a copy of it — since the
renewal retired that one for all of them. Another sign-in of the same account, made
separately, is its own and is left alone.

The tokens' signatures are not verified: the Identity Agent does not fetch the
providers' keys to check them. So this stops a mistaken file, or one for another
account, but not one forged to name this account. A body is trusted with the sign-in
it is lent for as long as it runs; this trusts it the same.

A renewed file is not lost when its return is. A lease that lapsed is remembered for
seven days, so a body that was out of reach can still give it back with what its run
renewed. A body tries a return again, waiting longer each time, while the Identity
Agent cannot be reached. If it still cannot, it keeps the renewed file in its own
directory, readable only by the host, and gives it back the next time it reaches the
Identity Agent, before it borrows again. The Identity Agent keeps a renewed file before it
takes the lease back: if its vault cannot be written at that moment, it answers that the
return should be tried again and keeps the lease, rather than saying "returned" and having
the body drop the only copy of a sign-in whose old refresh token is already spent.

**A brain that names its own sessions reports the one it started.** Codex does
this, and the next turn of the conversation resumes it.

## Consequences

- Ten AI agents on one subscription share one cap, as long as they share the
  account: through a sign-in that names it, or by reusing one sign-in.
- Two Claude tokens made separately for one account still count as two accounts.
  The front end steers people to reuse rather than make another token.
- A wrong key, a blocked key or an unreachable server is reported when the
  sign-in is made, not at the first run.
- A model server the Identity Agent cannot reach may still be reachable from the
  machines that run the AI agent. The check says so, and a front end may keep the
  sign-in anyway.
- A sign-in file is on a machine's disk only while a run uses it. A run killed
  outright leaves it until the next run of the same AI agent's brain on that machine
  removes it. On Windows, where a run that is stopped is ended outright, that is every
  stopped run.
- One run at a time uses an AI agent's home for a program on a machine.
- AI agents whose brains run as one operating-system user can read each other's
  homes. A brain user per AI agent separates them fully.
- On a machine where the brain runs as a user of its own, the host must also be
  allowed to start this program as that user, around the brain's program alone
  (`agent-host brain-env -- agent-host brain-home -- <program> *` in the sudoers
  rule). The wrapper runs there, and finds the sign-in in its environment, put there
  by `agent-host brain-env` from what it read on its own standard input; the sign-in
  never passes through sudo, which writes what it passes on to the system log
  (ADR-054).
- Grok renews its own sign-in, and whether that renewal retires the previous token
  is not documented, so it runs one at a time like Codex unless the owner raises it.
  When two runs on one account both renew it, the first renewal returned is kept and
  the second is dropped.
- A renewed sign-in waiting on a machine to be given back is kept there until it is,
  readable by the host alone.
- Not yet proven against the real programs: Codex reading the tool variables it is
  told to pass on (`env_vars`), Grok reading a model's settings from the run's
  home, and either program renewing a lent sign-in. The tests use stand-in
  programs.
