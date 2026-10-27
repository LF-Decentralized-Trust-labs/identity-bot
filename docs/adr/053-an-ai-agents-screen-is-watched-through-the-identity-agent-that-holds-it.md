# ADR-053 — An AI agent's screen is watched through the Identity Agent that holds it

**Status:** Accepted
**Date:** 2026-10-26
**Relates to:** ADR-046 (A machine becomes an AI agent's body by a person comparing six words), ADR-047 (AI agents talk through the Identity Agent that holds them), ADR-050 (One check for a controller's actions and an AI agent's capability calls), ADR-051 (An AI agent's brain is signed in once, and lent to a body per run)

## Context

An AI agent that uses a computer — clicking, typing, reading what is on the
screen — does its work on its body's screen. The people responsible for it need
to see that work as it happens, and sometimes to step in.

Until now that meant reaching the body's machine directly: a remote-desktop
server on the machine, a port opened to it, a tunnel or a shared network, and a
remote-desktop program on the person's computer. Each body needed its own
arrangement, none of it recorded who watched, and every arrangement was a way
into a machine that otherwise accepts no connections at all.

A body already keeps one connection open: sealed to the Identity Agent and
signed by its machine key, over which it collects its messages (ADR-047) and
borrows its brain's sign-in (ADR-051). A person already reaches the Identity
Agent from their app, wherever that app runs.

## Decision

**The screen travels over the two connections that already exist.** A body with
a screen says so on its sealed connection, and waits there to be watched. When a
person asks to watch, the Identity Agent opens a viewing for that body; the body
then sends pictures of its screen up its sealed connection, and the person's app
fetches them from the Identity Agent over its own signed connection. Nothing
connects to the body, and the body needs no open port, no remote-desktop server
and no particular network.

**A body says whether it has a screen, and the button appears only then.** The
word lasts a minute and is renewed while the body waits to be watched. A body
with no screen says so, and a body that has not said anything recently has none
as far as anybody is told. The app asks which AI agents have a screen now, and a
machine's screen is shown beside it in the list of the AI agent's machines.

**Pictures are sent only while somebody watches.** While watched, a body looks
at its screen a few times a second (four by default) and sends a picture only
when it changed, shrunk to at most 1280 pixels wide and compressed. A viewing
ends when its viewer closes it, or when nobody has fetched a picture for five
seconds; the body is then told to stop, and goes back to waiting. The Identity
Agent keeps only the latest picture of each body, in memory, and forgets it when
the last viewing of that body ends. Pictures are never written to disk.

**Watching and taking control are two actions in the one check.** Opening,
fetching and ending a viewing, and taking control and sending clicks and keys,
each need the default minimum score (ADR-050) unless the owner sets another for
that action. They are separate actions so that the owner can raise the score
for taking control without changing watching: a person who can click and type
on the AI agent's machine can do whatever that machine can. Both are open to
the owner and to an authorised controller. A browser session may watch and may
never take control.

**A viewing belongs to whoever opened it and to one body of one AI agent.**
Only its viewer can fetch its pictures, take control through it or end it. A
viewing asked for under another AI agent finds nothing, and a body that is
removed, or becomes another AI agent's body, ends every viewing of it.

**Clicks and keys travel back with the pictures.** The Identity Agent holds what
a person in control sent, checked and bounded, and hands it to the body with its
next picture. The body checks each event again and passes it to the screen. On a
machine running an X display the body reads the screen and passes clicks and
keys over the X protocol itself, with its XTEST extension, so no screenshot or
input program is needed on the machine.

**The body decides what it allows.** It runs with its screen offered for
control, for watching only, or not at all. A body offered for watching only says
it cannot be controlled, and ignores any click or key it is sent.

**Every viewing is recorded.** The start and end of watching, and of control,
are written to the signed governance record, naming who watched, which AI agent,
which body and for how long, and a refusal is recorded with its reason.

## Consequences

- Watching an AI agent works wherever the app works, in every build, with no
  set-up on the body beyond running it where it can see its screen.
- The Identity Agent carries every picture, so a screen costs it bandwidth while
  watched: a few compressed pictures a second, and nothing otherwise.
- The Identity Agent and the relays on the way see the pictures' sizes and
  timing; between the body and the Identity Agent the pictures themselves are
  sealed. Between the Identity Agent and the app they travel over the app's own
  connection, as everything else the app reads does.
- Clicks arrive with the next picture, so they lag by up to a quarter of a second
  while somebody is in control.
- A controller signs the path, the second and the body of a request, and a
  signed request is taken once. Each request about a viewing carries a fresh
  value in its body, so two identical requests in one second are not refused as
  one request sent twice.
- Only a body on a machine running an X display can show its screen today. A
  Mac or Windows body says it has none until reading and driving those screens
  is built.
- A refusal by the one check happens before a viewing's handler runs, and is
  answered with its reason but not written to the governance record.
