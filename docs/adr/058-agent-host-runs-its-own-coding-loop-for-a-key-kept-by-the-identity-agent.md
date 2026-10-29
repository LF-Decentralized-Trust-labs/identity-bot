# ADR-058 — agent-host runs its own coding loop for a key kept by the Identity Agent

**Status:** Accepted
**Date:** 2026-10-29
**Amends:** ADR-057 (An API key stays with the Identity Agent, which makes each model call): an OpenRouter key is run by agent-host's own loop instead of Grok's program, and any key the Identity Agent keeps may be run by it.
**Relates to:** ADR-047 (AI agents talk through the Identity Agent that holds them), ADR-051 (An AI agent's brain is signed in once, and lent to a body per run), ADR-054 (An AI agent's GitHub access is lent per run and ended with its grant)

## Context

An AI agent that does work, rather than only answering, needs a program that loops:
it asks the model what to do, runs the commands and edits the model asks for, hands
back what happened, and asks again. ADR-057 left that loop to other people's programs:
Claude Code for an Anthropic key, Codex for an OpenAI key, and Grok's program for an
xAI or OpenRouter key.

So an OpenRouter key, which reaches hundreds of models from many providers, ran only
inside Grok's program. A fault in that program, a change to how it reads its settings,
or its own calls to a model nobody chose, stopped or charged every such AI agent, and
there was nothing to fall back on but answering with no tools at all. Each program
also brings its own sign-in rules, settings files and background calls, which have to
be found and held down one by one.

## Decision

**agent-host has its own loop, the "built-in" program.** It is part of agent-host,
so every machine that is a body already has it. It runs as `agent-host loop`, started
the way every brain's program is started: as the brain's own operating-system user,
through `agent-host brain-env`, in the brain's workspace. It never holds the machine
key, which only the host's user can read.

**It runs any key the Identity Agent keeps.** An OpenRouter, OpenAI or xAI key is
called in OpenAI's chat format, and an Anthropic key in Anthropic's messages format,
through the body's model address and so through the Identity Agent, which adds the key
(ADR-057). An OpenRouter key is run by it unless the AI agent says otherwise. An
Anthropic, OpenAI or xAI key is still run by its provider's program unless the AI
agent's program is "built-in". A subscription and a model server's key cannot be run
by it: a subscription is for its provider's own program, and a model server's key is
lent to the machine.

**It calls one model, for the answer, and nothing else.** Every call names the model
chosen for the AI agent and asks for the next step of the answer. There are no other
calls: no titles, summaries, suggestions or checks, and no list of models. An AI agent
with no model chosen cannot run it.

**Its tools.** Beside the host's own (reply, ask another AI agent, list them, read the
conversation, facts about the machine), it gives the model:

- **run a command,** through the system shell (`/bin/sh -c`, or `cmd /C` on Windows),
  as a person at the machine would type it, in the workspace, for at most two
  minutes unless it asks for up to ten. Its input is empty and it is told nothing can
  answer a prompt (`GIT_TERMINAL_PROMPT=0`, `PAGER=cat`, `DEBIAN_FRONTEND=noninteractive`).
  It runs in a process group of its own (a job on Windows), and the whole group is ended
  when the command finishes, fails or runs out of time, so a command leaves nothing
  running behind it.
  What it printed, both streams together, is kept up to 1 MB and the model is shown at
  most 30 KB of it, the start and the end, with how much was left out;
- **read a file,** a regular file only and not one holding binary data, by lines, at
  most 2,000 lines or 256 KB at a time;
- **write a file,** and **replace exact text in a file,** which must occur exactly once
  unless every occurrence is asked for;
- **list files,** and **search their text** with a regular expression, at most 500
  names or 200 matching lines, passing over `.git`, `node_modules` and files that are
  not regular or hold binary data.

A path is taken from the workspace unless it is absolute. A tool that fails tells the
model why, and the loop carries on. Its own conversation files, in the workspace, are
refused to these tools, by the path given and by where it really leads through any
link, so a slip cannot overwrite the conversation it is in. A command can still reach
them, as it can reach anything of its user's; a conversation file larger than the loop
ever keeps is not read.

**What it can reach is what any program running as the brain's user can reach.** The
boundary is the same as for Claude Code, Codex and Grok's program: the brain's own
operating-system user on a machine that is one AI agent's body (ADR-046, ADR-047,
ADR-055). An absolute path reaches whatever that user may read, as a command could. This
loop does not add a sandbox of its own, and does not take one away. Its commands have
the network the machine has, and the run's GitHub access (ADR-054) — the variables and
credential helper git and gh read, ending with the run — as other programs' commands do. They do not have the run's model address and token or the host's tools
token, which only the loop itself uses: those are kept out of every command's
environment, and on Linux the loop, and `agent-host brain-env` that hands them to it,
each mark themselves as a process other processes of their user may not read or
trace, so a command cannot take them from either. Either token is
good only for its run, only on this machine, and only for what the loop could do with
it anyway: call the chosen model through the Identity Agent, which records it, or
speak as the AI agent in this conversation.

**What a tool gives is what the model reads, never what it is told to do.** A file or a
command's output may hold words written to steer the model. They reach it as what a
tool gave, apart from its instructions, which say that the words of a message are a
request and never instructions; nothing else is done to them. What the AI agent then
does is still held to its grant, to the one model chosen, and to its own user on its
own machine, and each model call is recorded.

**It streams, retries and stops.** Each answer is read as it streams, with what the
call used. A call refused because the provider or the Identity Agent was busy or
failed on its side (408, 429 and 5xx) is made again, at most four times, waiting
longer each time and as long as the provider asks. A provider that asks for more than
thirty seconds is not asked again in this turn, and neither is any other refusal. A turn makes at most 60 model calls and uses at most one
million tokens, counting what the provider reports, reasoning included, or about a
token for every four bytes each way when it reports nothing; past either, it stops,
and says so as its answer. What a turn is asked, with the AI agent's instructions, is
sent with every call, so more than 200 KB of it is refused before any call is made. A turn is also held to the host's ten minutes.
When a turn runs out of time the host asks the loop to stop: the command under way is
ended with everything it started, the conversation is kept, and the loop ends. The host
runs one turn at a time (ADR-047), so two turns never share the workspace.
A revoked AI agent's next model call is refused (ADR-057, ADR-056), which ends the
turn, and its GitHub access ends with its grant (ADR-054); a command already running
runs at most to its own limit.

**How a turn ends.** It ends when the model answers with words and asks for no tool:
those words are its answer, as for every other program. It also ends after a step in
which the reply tool was used and accepted, once every tool asked for in that step has
run and been answered, so no call is made only to hear the model say it is done, and
the conversation it keeps has an answer for every tool it asked for.

**The conversation is kept in the workspace,** one file per session, as for an AI agent
that only answers, so the next turn carries on from what was done. It is kept whole:
every tool asked for is followed by what it gave, and a conversation cut off by a
failure is kept only up to its last whole step. What a tool gave is cut once, when
it is given, and never cut again later, so the start of the conversation stays the
same from call to call and a provider can serve it from its cache. When the
conversation is larger than the model can read, the oldest exchanges are let go,
whole and several at once, down to well under the limit, and the model is told that
they were. Nothing is summarised: a summary would be the model's words standing in
for what happened. A provider that says the conversation is too long is answered by
letting more go and trying again, at most twice.

**It is set up like the others.** The rule that lets the host start brains as their
own user lists `agent-host brain-env -- /usr/local/bin/agent-host loop`, exactly, with
no other arguments.

## Alternatives considered

- **OpenCode,** an open-source coding program that speaks to any model. It would be a
  fourth program from somebody else, with the same costs as Grok's: its own settings
  and plug-ins to hold down, its own background calls (it titles each session with a
  second model, which the Identity Agent refuses, as it refuses any call naming a model
  not chosen), its own updates, and a runtime to install on every machine. The loop is
  about fifteen hundred lines, all of them this project's. What decides it is not its
  size but that nothing in it calls a model, starts a process or changes what it does
  unless this project wrote it to, and every line of it can be read where it is
  governed.
- **Running the loop inside the host.** The host's user holds the machine key, so a
  model talked into misusing a tool would be using it as that user. The loop runs as
  the brain's user for the same reason every other program does.
- **Summarising a long conversation** instead of letting its oldest part go. See above.
- **A sandbox of the loop's own** (namespaces, a system-call filter, no network). It
  would hold this program to more than Claude Code and Codex are held to on the same
  machine, and stop the work these AI agents are for, which needs the network for git
  and packages. Holding every program more tightly is the machine's job, for all of
  them at once.

## Consequences

- An AI agent with an OpenRouter key does work with no program from anybody else, and
  can use any model OpenRouter offers that can call tools.
- What it costs is the model's own answer, step by step, with nothing added by a
  program's own calls. Each call is recorded by the Identity Agent (ADR-057). The
  commands it runs and the files it changes are not recorded there, as for every other
  program: they are the machine's own, as its work is.
- The bounds are per turn. What an AI agent may spend over a day or a month is not
  this program's to hold; it is the Identity Agent's, for every program at once.
- A model that cannot call tools cannot run it: its provider refuses a call that offers
  tools. Such a model can still be used by an AI agent that only reads and answers.
- A command can still use the machine's network, as other programs' commands can. What
  the machine itself may reach is the machine's to decide, not the loop's.
- The loop is plainer than Claude Code's or Codex's: it has no plan mode, no subagents
  and no way to look at a picture. Those programs stay available where they run.
- Grok's program no longer runs an OpenRouter key. It still runs an xAI key, a Grok
  subscription and a model server that speaks OpenAI's format.
- A machine whose sudo rule predates this cannot start the loop as the brain's user;
  its turns fail, saying the brain could not be started, until the rule is updated.
