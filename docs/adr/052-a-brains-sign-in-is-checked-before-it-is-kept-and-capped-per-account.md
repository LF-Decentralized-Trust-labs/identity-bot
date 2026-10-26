# ADR-052 — A brain's sign-in is checked before it is kept, and capped per account

**Status:** Accepted
**Date:** 2026-10-26
**Amends:** ADR-051 (An AI agent's brain is signed in once, and lent to a body per run): the cap counts an account rather than one AI agent's sign-in, and the brains a body can run from a lent sign-in now include Codex, a Grok subscription, OpenAI and OpenRouter keys, and servers that speak OpenAI's format
**Relates to:** ADR-047 (AI agents talk through the Identity Agent that holds them), ADR-050 (One check for controller actions and AI agent capability calls)

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
runs, whichever AI agents hold it. The account is identified in one of two ways.

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

When AI agents on one account have different caps, each borrow is checked against
the borrower's own cap, counting every run on the account. A lease records the
account it counts against. A lease from before this decision counts against its AI
agent alone.

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

A kept sign-in can be checked again later. That check is recorded.

**Two kinds of sign-in are never sent anywhere by the Identity Agent.**

- **A Claude subscription's token is for Claude Code alone.** Anthropic does not
  allow anyone else to use a Claude.ai token, so the Identity Agent never uses it
  itself. Claude Code checks it, on the computer that signed it in.
- **A Codex or Grok sign-in is the file the program wrote when the person signed
  in.** That sign-in is proof it worked at that moment. The Identity Agent reads
  the file for its account and checks it is one, but does not use it.

**A front end lists the brains a body can run.** It offers only those:

| Brain | Program a body runs |
|---|---|
| A Claude subscription | Claude Code |
| An Anthropic key | Claude Code |
| A server that speaks Claude's format | Claude Code |
| A ChatGPT plan (Codex) | Codex |
| An OpenAI key | Codex |
| An xAI key or Grok plan | Grok |
| An OpenRouter key | Grok |
| A server that speaks OpenAI's format | Grok |

A Google key is still kept if sent, but is not offered: no program a body runs
takes it yet.

**A program that keeps its sign-in in a file is given the file for one run.**
Codex and Grok each get a home of the body's making, one per program, under the
home directory of the user the brain runs as. Their sessions stay there, so a
conversation can carry on in the next run. The home holds no sign-in between runs.

- **A small wrapper writes the sign-in.** It runs as the brain's user, writes the
  sign-in file into that home, runs the program and reads the file back. Then it
  removes the file. It removes it the same way when the run fails or is stopped.
  Before a run, it also removes a sign-in file a crashed run left behind.
- **The wrapper reports on its standard output alone.** Its error output becomes a
  failure notice, so the sign-in never goes there.
- **The program's own settings and sign-in are not read.** A key reaches the
  program as an environment variable.
- **A model at a sign-in's own address is described in the program's settings for
  the run.** That covers OpenRouter and servers that speak OpenAI's format. The
  settings name the variable that holds the key, never the key.
- **Codex is told about the body's tools on its command line.** The command line
  names the variables that hold the tool address and token, never their values.

**A sign-in a program renewed during a run is kept.** Codex and Grok renew their
own tokens while they run. The token they were lent may stop working once they
have. So the renewed file goes back with the lease, sealed like everything a body
sends. The Identity Agent keeps it in place of the one lent, and of every copy
other AI agents share, but only:

- while the kept sign-in is still the one that was lent;
- while the renewed file is for the same account.

A renewed file for another account, or one returned after the sign-in was
replaced, changes nothing.

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
  outright leaves it until the next run on that machine removes it.
- One run at a time uses a program's home on a machine. Two AI agents running the
  same program as the same user on one machine take turns.
- On a machine where the brain runs as a user of its own, the host must also be
  allowed to start this program as that user. The wrapper runs there.
- Grok renews its own sign-in, and whether that renewal retires the previous token
  is not documented. When two runs on one Grok account both renew it, the first
  renewal returned is kept and the second is dropped. If that proves to retire the
  kept token, the cap for a Grok subscription should be one, as it is for Codex.
- Not yet proven against the real programs: Codex reading the tool variables it is
  told to pass on (`env_vars`), Grok reading a model's settings from the run's
  home, and either program renewing a lent sign-in. The tests use stand-in
  programs.
