# ADR-034 — An instance is told who may claim it, before anyone can reach it

**Status:** Accepted
**Date:** 2026-08-06
**Builds on:** ADR-032 (an identity can name who owns it, from its first event)
**Refined by:** ADR-036 (the identifier sent ahead is pairwise, never a root)

## Context

Some Identity Agents are set up by one party and claimed by another.

Somebody buys an always-on Identity Agent and it is started for them before they have
touched it. A family member configures a small computer for a relative. An
organisation has an Identity Agent prepared by whoever runs its machines. In each case
there is a window — sometimes seconds, sometimes days — where the Identity Agent is
running, reachable, and belongs to nobody yet.

ADR-032 settled what happens at the *end* of that window: the identity names its
owner in the event that creates it, as an anchor seal, and because a KERI
inception event's identifier is derived from its own content that naming cannot
later be removed. It says nothing about how the owner's identifier reaches an
Identity Agent that has no owner to authenticate.

That gap had an answer in practice, and the answer was wrong.

**What it used to do.** The Identity Agent minted a claim code for itself and served it on
an unauthenticated route. Anyone who could reach a fresh Identity Agent could ask for the
code and use it to become its permanent owner. The route had to be
unauthenticated — there was no owner yet to authenticate against — so the secret
that decided ownership was published to whoever asked first.

On a machine on somebody's desk that is survivable, because reaching it means
being in the room. On a machine reachable from the internet it is not survivable
at all, and "reachable from the internet" is the whole point of an always-on
Identity Agent. The first person to find the address owned it.

The defect was not the missing authentication. It was the direction: **the Identity Agent
was deciding something it cannot know.** An Identity Agent that has just started has no
way to find out who paid for it, who was promised it, or who is coming. Whoever
started it knows all three.

## Decision

**An Identity Agent does not decide who owns it. It is told, before anyone else can
reach it, and it refuses everyone else.**

Concretely:

1. **The Identity Agent mints no claim code and publishes none.** Its pairing offer
   discloses the pairwise AID it is about to publish as an OOBI anyway, and an
   attestation of what it is running where the hardware can produce one. Nothing
   that decides ownership.

2. **Whoever provisions it mints the claim token** and pushes it inward —
   `POST /api/provisioning/expect`, carrying the token and the AID that will
   present it.

3. **That must happen while the provisioner is the only thing that can reach the
   Identity Agent.** Ordering is the security here, not decoration. Once the Identity Agent is
   published, anyone can speak to it; being first has to be guaranteed, and it is
   only guaranteed before publication.

4. **The first expectation wins and the rest are refused.** An Identity Agent takes the
   answer it is given once. A second caller — including one that got there
   through a race — is told it has already been told.

5. **Claiming checks all three things**: the token matches, the presenting AID
   matches the one the Identity Agent was told to expect, and the owner's public key is
   present and well formed. Then, and only then, the Identity Agent founds its identity
   naming that owner per ADR-032, and refuses every later claim permanently.

6. **The expectation is memory, not storage — on purpose.** An Identity Agent that has
   restarted has forgotten, and whoever provisioned it re-arms it as part of
   bringing it back. That keeps the authority with the party that has it, rather
   than letting a stale file on disk decide ownership after a restart.

Two routes stay unauthenticated, and the reasoning has to hold because an
outside reader can check it: `GET /api/provisioning/pairing` and
`POST /api/provisioning/expect`. Both run only while the Identity Agent has no identity,
both stop answering the moment it has one, and neither discloses anything that
is not about to be published anyway. An Identity Agent with an owner answers `409` to
both — the window closes on success and does not reopen.

## How the claim reaches the person, and why the number of codes differs

*Added 2026-08-13, because the answer looks inconsistent from the outside and is
not.*

Being told who may claim an instance settles WHO. It says nothing about how the
claim token gets from wherever it was minted to the device that will use it, and
that is a different question with a different answer per case. **The number of
codes a person is shown follows entirely from whether there is a hand-off
between devices.**

There is a hand-off whenever the party that STARTS the setup is not the party
that HOLDS the key. A code — shown on a screen, scanned by a phone — is how the
token crosses that gap. Where one device does both ends, nothing needs to cross
and no code is shown.

| Case | Codes | Why |
|---|---|---|
| A computer in front of you | **one** | The computer shows it; the phone scans; there is one exchange. |
| An instance you asked for, from the device holding your key | **none** | The same app asked for the instance and claims it. Nothing crosses. |
| An organisation on a computer in front of you | **one** | The organisation is set up at a desktop; the key is on the phone. |
| An organisation on a hosted instance | **two** | The same gap, plus a wait: one to agree, and one when the machine is up. |

**The second code in the last row is not ceremony.** The instance does not exist
when the first is scanned, so there is no token to carry yet. The window that
token stands for starts when the SECOND code appears — when the person can
actually act — rather than when the instance was asked for, or a slow start
would spend the window before anybody saw it.

**A code is never what authorises the claim.** It is a hand-off, and it is
readable by anyone who can see the screen. What authorises is the claim proving
control of the identity the instance was told to expect. That is why the count
can differ between cases without the security differing: showing no code, one,
or two changes how the token travels and nothing about what is checked when it
arrives.

## Consequences

**Whoever provisions an Identity Agent can decide who owns it.** That is not a weakening,
it is the honest shape of the situation: they started the machine, so they were
always able to hand it to somebody else instead. Naming the owner in advance
makes the decision explicit and, once claimed, permanent and publicly checkable
from the key event log. What it removes is the *stranger's* ability to decide.

**An Identity Agent nobody was expecting cannot be claimed at all.** An Identity Agent that was
never told what to expect accepts nothing from anybody. That is the right
failure — a claimable-by-anyone Identity Agent is worse than an unclaimable one, and the
unclaimable one is recoverable by telling it.

**The provisioner holds a mapping** from claim token to owner AID, for as long as
the claim is outstanding. That is real and worth stating plainly: the party who
started the Identity Agent knows who it was started for. They already know, because
somebody asked them for it.

**The person doing the claiming must still look.** Everything above defeats the
attacks that were anticipated. The owner's app additionally mints a nonce and
refuses any returned link that does not carry that nonce back — which stops an
unsolicited link from asking somebody's Identity Agent to adopt a machine a stranger
controls — and then shows the address in plain text and waits. That last step is
what covers the attacks that were not anticipated.

## Alternatives considered

**Authenticate the pairing route.** There is nobody to authenticate as. This is
the state before an owner exists, which is the state that needs solving.

**Let the first claimant win, and make the address hard to guess.** This is what
was happening. It makes ownership a race, and an address that is published in an
OOBI is not a secret.

**Have the Identity Agent verify a payment receipt.** It moves the trust to the payment
provider and requires the Identity Agent to talk to one, which an Identity Agent that has not been
claimed should not be doing. It also fails for every Identity Agent that was not bought.

**Persist the expectation to disk so it survives a restart.** Tempting, and
rejected: it would let a file left on disk decide ownership later, and the party
who should be deciding is available and is already involved in the restart.
