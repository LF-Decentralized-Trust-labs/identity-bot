# ADR-055 — A new machine for an AI agent is made by a provider, and approved by a person

**Status:** Accepted
**Date:** 2026-10-27
**Amended:** 2026-10-27 — a machine nobody may use any more is destroyed without anybody asking
**Relates to:** ADR-046 (A machine becomes an AI agent's body by a person comparing six words), ADR-050 (One check for a controller's actions and an AI agent's capability calls), ADR-051 (An AI agent's brain is signed in once, and lent to a body per run), ADR-054 (An AI agent's GitHub access is lent per run, and ended with its grant)

## Context

An AI agent runs on a machine — its body — which a person enrols by running
`agent-host enrol` on it and comparing six words (ADR-046). Each AI agent is best
kept on a machine of its own: its own kernel, disk and network, so a brain that runs
commands cannot see other AI agents or the host. Making such a machine by hand for
every AI agent — building it, installing agent-host, copying an enrolment string in —
does not scale, and is where mistakes happen.

AI agents also differ in what their machine must have. One that uses a computer
needs a screen and a browser; one that writes code needs a toolchain; one that only
coordinates others needs neither. That is a different question from which services
an AI agent may use. Services are capability grants, kept the same wherever it runs
(ADR-054), so moving an AI agent to another machine never changes what it may reach.
What the machine provides decides where it can run.

## Decision

**What the machine must provide is kept on the AI agent.** Its configuration carries
`machine.provides`: a list from a fixed vocabulary — `screen` (a virtual screen that
never sleeps or locks, and a browser), `toolchain` (git, compilers, package managers),
`xcode` (Apple's toolchain, on a Mac only). Empty is a machine that only carries
messages. An unknown word is refused rather than dropped. It is set when the AI agent
is created or with `PUT /api/mcp/agents/{id}/machine`, and a configuration change that
does not mention it keeps it. It grants nothing.

**A provider is a body granted `agent.machine.provide`.** A host that can make
machines is enrolled like any other machine, as the body of an AI agent whose grant
gives `agent.machine.provide`. That capability's executor type is `body_service`:
work the Identity Agent hands to a body, never invoked through the gateway, checked
with the same one check as any capability (ADR-050). Revoking that AI agent, or its
grant, or removing its body, stops it being given work.

**The provider collects work the way a body collects messages.** `agent-host provide
--program PATH --offers screen,toolchain` long-polls
`GET /api/agent-host/machine-requests`, sealed and signed by its machine key, saying
each time what the machines it makes can provide. A provider that has not asked for
two minutes is shown as offline.

**A person chooses where an AI agent runs.** `GET /api/mcp/agents/{id}/machines-that-fit`
lists each live provider, whether it provides everything the AI agent needs and what
it lacks, and what a machine set up by hand must have. Asking a provider for a machine
(`POST …/machine-requests`) records a request naming the AI agent, the provider, the
needs at that moment, and a machine name made from the AI agent's name — `agent-`,
lowercase letters and digits joined by single dashes, and four random hex digits — so
that it is safe to hand to a program. Both the Identity Agent and the provider accept
only names of exactly that shape, so a name can never be that of anything else on the
host, such as an Identity Agent's own virtual machine. A provider is never asked for what it does not offer, and an AI agent has
one new machine on its way at a time, until its words are approved or it is cancelled.

**The provider makes the machine, and only a person makes it a body.** The provider
calls the operator's program three ways: `make NAME NEEDS`, `enrol NAME` with a
one-time enrolment string on standard input, and `remove NAME`. How the machine is
made — a virtual machine, a container, a cloud instance — is that program's business.
Its environment carries the AI agent's display name as `AGENT_MACHINE_FOR`, which a
person typed, so the program must treat it as text and never put it into a shell
command; `NAME` and `NEEDS` are only letters, digits, dashes and commas.

**A provider touches only the machines it made.** The name comes from the Identity
Agent, so a name alone is never enough to destroy anything. The environment also
carries the request's id as `AGENT_MACHINE_REQUEST` and the provider's own binding as
`AGENT_MACHINE_PROVIDER`. `make` records both with the machine; `enrol` and `remove`
refuse a machine that does not carry the same two, and `remove` of a name that has no
machine at all succeeds without doing anything. `make` exits 3, having touched
nothing, when something of that name already exists on the host, and the provider
then reports the request failed and never asks for that machine to be removed. A
machine made by hand, by another tool, for another request, or by a provider that has
since enrolled again, is therefore left alone, and the operator removes it.
After `make`, the provider asks for the enrolment string for that request
(`POST /api/agent-host/machine-requests/{id}/enrolment`), once per request. It is
the same string a person would be given: good once, for that AI agent, within the enrolment window, and
it travels sealed to the provider's keys. The program hands it to the new machine,
whose `agent-host enrol -` reads it from standard input so that it never appears on
a command line. `agent-host enrol` waits for a person's decision, so the program
starts it in the background on the new machine and prints the six words it shows
once the machine has asked. The provider reports them, and the Identity Agent matches
them to the machine that asked to become that AI agent's body since that enrolment
string was given — waiting for approval, or already approved by a person before the
report arrived; a provider cannot claim a machine that was already there, and words
no such machine shows are refused. The person then approves, as for any machine. A provider can report a machine made,
enrolling or failed, and never ready: a request is ready only when a person has
approved its machine.

**Removing the machine destroys it.** Removing a body that a provider made ends the
body first, as any removal does, then asks its provider to destroy the machine; the
provider reports it removed, and retries a removal that failed. A machine whose words a
person rejects is destroyed the same way. Cancelling a request whose machine was never
made simply ends it; cancelling one still being made, or waiting for approval, has it
destroyed. A provider that fails part way destroys
what it made and reports why, and one that restarts while making a machine destroys
that machine rather than leaving it half made.

**A machine nobody may use any more is destroyed without anybody asking.** When an AI
agent's grant is revoked, lapses, or the AI agent is gone, every machine made for it is
ended: its body stops being admitted first, its provider is told to destroy the
machine, and its body credential is withdrawn in the registry; a withdrawal that cannot
be written yet is tried again by the next sweep. This happens as soon as the credential
is revoked, in the background, and a sweep every minute catches the rest. The same sweep destroys a machine whose six words nobody approved
before its enrolment window ran out, and one whose enrolment string ran out before it
asked at all. Ending a request whose string was given but never used voids that string,
so no machine can use it afterwards.

**Everything is recorded.** Each step — requested, enrolment string given, making,
enrolling, failed, removing, removed, cancelled — is written to the signed record as
the AI agent the machine is for.

## Consequences

- An AI agent gets a machine of its own, with only what its work needs, from one
  choice in a front end. No person copies an enrolment string or logs into the host.
- Only a person's approval makes a machine speak as an AI agent; a provider that
  misbehaves can make machines, never bodies. What the approval rests on changes. A
  person setting up a machine compares the words on its screen with the words in the
  front end. For a machine a provider made, nobody reads its screen: the provider's
  report, sent over its own signed and sealed channel, is what ties the waiting
  request to the machine it made, and a front end should say so rather than ask the
  person to compare two copies of the same words.
- What a provider can build is the operator's program, not this repository's: the
  same mechanism serves a virtual-machine host, a container host or a cloud account.
- A brain the new machine needs must be installed by that program. Its sign-in is
  still lent per run (ADR-051).
- An AI agent may install tools inside its own machine as it works; that changes
  nothing outside it, and the machine is destroyed when the AI agent's body is
  removed. Reaching an outside service is still a grant (ADR-054).
