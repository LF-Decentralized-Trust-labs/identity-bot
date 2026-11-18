# ADR-041 — One neutral scheme for the protocol's device codes

**Status:** Accepted
**Date:** 2026-09-06
**Extends:** ADR-040 (The protocol's deep-link namespace is vendor-neutral)
**Relates to:** ADR-006 (Standardized Topology)

## Why this exists

ADR-040 settled the namespace for one code — the controller offer — and named it
`identity-agent://`. It left three sibling codes still under a vendor scheme and
never said what the whole namespace is *for*, nor which of these strings are meant
to be **shared and tapped** versus only **scanned**. This decides both, so there is
one answer instead of a per-code accident.

## The vocabulary — three string types, and what "deep link" means

A **deep link** is any link that, when tapped, opens an app instead of a web page.
There are two kinds and both are deep links: a **custom-scheme** link
(`identity-agent://…`), which the OS routes to *any app that registered that
scheme*; and a **universal link** (`https://…`), which the OS routes to *the one
app that owns that domain*, falling back to the browser. Neither is more "real"
than the other; they trade off differently (below).

The protocol moves three kinds of string:

1. **Device code (custom scheme).** A short, self-contained string a device shows —
   `identity-agent://controller?…`, `identity-agent://pair?…`. It carries everything
   in the string; nothing is fetched. Its primary transport is **a QR the other
   device scans**, or a paste — read *in the app*, so the OS is not involved and the
   scheme is simply how the app's scanner recognises one of the protocol's codes.
   Some device codes are *also* meant to be shared and tapped (see "Shareable");
   there the OS routes them by scheme.
2. **Pointer (https).** `https://host/i/{token}` — a normal web URL pointing at a
   relay, **fetched over the network**. This is the universal "Ask" rail (login,
   add-contact, credentials). Because it is https it is *already* a shareable,
   tappable universal link with a browser fallback.
3. **OOBI (https).** `https://host/public/oobi/{aid}` — a KERI address an agent
   fetches to learn another identity's key state. Also plain https.

## Scanned versus shared — which codes are which

The distinction that was muddy: not every code is meant to be *shared with another
person and tapped*. Two of them are you-and-your-own-device and only ever scanned.

| Code | Shared with another person? | So it is |
|---|---|---|
| Ask / transaction (`/i/{token}`) | **yes** — you send someone a login / contact / credential request | shareable + tappable |
| controller offer | no — your two own devices, in the same room | scanned / pasted only |
| pair a computer | no — you and your own computer | scanned / pasted only |
| rent / adopt a box | no — a web page returning *you* to *your own* app | tapped, but only by you, from a browser |

So "how do people share these?" has a precise answer: the **Ask** is the one that
gets shared, and it is already an https universal link. The device codes are shown
on one of your screens and scanned by another of your screens — nobody shares
"pair my laptop" with a stranger, so it never needs to be a tappable link.

## The inventory today

| Code | Scheme | Purpose | How it travels | OS-routed? |
|---|---|---|---|---|
| `…://controller` | **identity-agent** (neutral) | a computer offers to act for an identity | QR / paste, parsed in-app | no |
| `…://pair` | grapeid (branded) | claim a computer / found an org on a box | QR / paste, parsed in-app | no |
| `…://rent` | grapeid (branded) | a machine is reserved for you | tapped from a web page | yes (individual app) |
| `…://adopt` | grapeid (branded) | finish provisioning a rented box | tapped from a web page | yes (individual app) |

Three of the four still carry a vendor's name in the protocol's own wire namespace.
`adopt` is the sharpest case: it lives in the neutral core library yet is driven by
a branded scheme, with no scheme constant to point at.

## The decision

**One neutral scheme — `identity-agent://` — for every device code the protocol
defines.** Rename `pair`, `rent`, and `adopt` to it, exactly as `controller` already
is; keep the scheme as a single shared constant a downstream build may override for
its own displayed scheme, and keep every on-wire signed tag neutral and
non-overridable (per ADR-040). https pointers and OOBI are unchanged.

And, for the codes that ARE shared (the Ask), **support both deep-link kinds**: the
Ask stays an `https://` universal link — clickable anywhere, opens the app when it is
installed, falls back to a web page that guides the recipient otherwise — AND the
neutral `identity-agent://` scheme is registered by every conforming app, so a tapped
neutral-scheme link opens whichever identity-agent app the recipient has. https gives
reach; the neutral scheme gives "any conforming app." A shared transaction should
offer whichever the sender's context makes available, and both resolve to the same
in-app handler.

### Why neutral, not branded — the three reasons

- **Interoperability, decisively.** A scheme is only an agreed prefix. If one
  implementation emits `vendor-a://controller` and another only reads
  `vendor-b://controller`, a code from one will not parse in the other — a
  per-vendor scheme *is* a per-vendor silo. An open protocol whose codes only work
  inside one vendor's app has given up the thing it exists for. One agreed neutral
  scheme is what lets any conforming app read any conforming code. This is the whole
  ballgame; the rest is minor.
- **Nobody sees it.** These codes are scanned or pasted. The person points a camera
  at a square; the scheme prefix is never read, typed, or shown. Branding a string
  no human looks at buys no recognition and no trust — it only spends the
  interoperability above.
- **Brand belongs in the app, not the wire.** The name, the icon, the colours, the
  copy — those are where a product is itself, and they are untouched by this. What a
  neutral protocol must not do is make its own wire format say a vendor's name.

So a commercial scheme fork is not a feature to preserve; it is the exact thing that
would stop a second implementation from reading the first one's codes.

## How opening works, and the one honest limit

- **Scanning (the primary path) is fully vendor-agnostic and needs no OS
  registration.** A device shows the code as a QR; another device's identity-agent
  app reads it with its camera and parses it against the neutral scheme. Any
  conforming app scans any conforming code — this is where the interoperability
  guarantee actually lives, and it costs nothing.
- **Tapping a shared link is where the deep-link kinds trade off.** A neutral
  **custom scheme** opens *any* conforming app but has no web fallback (tap it with
  no such app installed and nothing happens) and, if two are installed, the OS
  prompts which to use. An **https** universal link is clickable everywhere, opens
  the app when installed and shows a web page otherwise, but is owned by one domain,
  so it opens *that* app, not any. Neither alone is both vendor-agnostic and
  fallback-safe — which is why the shared code (the Ask) offers both, per the
  decision above.
- **`rent` / `adopt` are not shared at all** — they are a web page you opened
  returning *you* to *your own* app. They are the only strictly OS-routed device
  codes today, registered by the one app that started the flow, so there is no
  multi-vendor ambiguity to resolve; they simply move to the neutral scheme like the
  rest.

The genuinely hard problem — a tapped link opening one specific app *chosen from
several* conforming apps — is a platform limit, not a protocol one, and the neutral
scheme plus scanning covers every case that matters now without pretending to solve
it.

## Consequences

- One scheme constant governs all device codes; renaming the three branded verbs is
  a constant change on each, plus the parser tolerating the old value for one
  release if any are already registered with an OS.
- The `pair` scheme constant, currently duplicated across two apps, should move to a
  shared package so there is one definition to neutralise and keep neutral.
- `adopt`'s parser reads only the query parameters and never inspects the outer
  scheme, so the core library already depends on no scheme; only the emitter (a web
  page) and the examples/tests move to the neutral value. Nothing in the core changes.
- No shipped external consumers exist for any of these codes, so migration cost is
  near zero — the reason, again, to settle it now.

## Not decided here

Whether the product's own OS URL registration keeps a branded scheme for
*non-protocol* uses (marketing links, app-open) is a product choice and outside this
ADR; it only forbids a vendor scheme in the protocol's *own* device codes.

## Amendment 1 (2026-11-18): a computer asks to act for an identity by an Ask, not by a device code

**Status:** Accepted. **Amends:** this ADR's inventory and "Scanned versus shared", and ADR-040's
premise that the controller offer travels whole in the QR. **Relates to:** ADR-006 (a controller),
ADR-021 (the Ask and its pointer).

### What changes

Asking to act for an identity is no longer a device code. A computer that wants to act for an
identity shows a **bare Ask pointer**, `https://{agent}/i/{token}`, and the owner answers it through
the same scan gate, the same `ASK1` envelope and the same fetch as a sign-in. It is action **8,
`act_for_identity`**, in `identity-agent-core/actions/registry.json`. The self-contained
`identity-agent://controller?…` code, about 330 characters of key, address, time and signature in one
QR, is withdrawn as what a computer shows.

Why it matters: one code on a screen should mean one exchange. A dense code that looks like every
other code but is answered by a different mechanism behind it gives two protocols for the same
gesture, and a second scanner path to keep correct. It also scans badly: a pointer under 60
characters is a sparse QR any camera reads at a glance.

### The problem the device code was solving, and how this solves it instead

The offer travelled whole because the computer's own core cannot be reached from the owner's phone:
there was nothing for the phone to fetch from. But the computer can reach the Identity Agent it is
asking to act for (it must, to act for it), and so can the owner's phone. So:

1. The computer's core signs its offer exactly as before: the prefix
   `identity-agent-controller-offer-v1`, its key, the Identity Agent's origin and the time,
   newline-separated, with the key in its secure hardware (ADR-040's signed bytes do not change).
2. The computer leaves that signed offer at the Identity Agent it names:
   `POST {agent_origin}/api/controller/requests`. The Identity Agent checks the offer and answers with a
   token and the time it expires.
3. The computer shows `{agent_origin}/i/{token}`. The pointer is built on the origin the computer
   signed, so the place the code points and the place the offer names are the same place.
4. The owner's Identity Agent fetches the Ask at the pointer (`GET /i/{token}`, as for any Ask),
   checks the computer's signature over the offer, that it is fresh, and that it was served by the
   Identity Agent it names, and shows the person what is asking.
5. The person's approval is the **grant**: the owner's own signed `POST /api/controllers` to that
   Identity Agent, unchanged. The grant retires the token.

### Who may leave a request, and what bounds it

Anybody may leave one, without credentials. The computer has no standing at the Identity Agent yet,
and asking is how it gets some. What makes that safe:

- **It never grants.** Leaving, fetching, previewing and approving on the scan gate record nothing.
  Only the owner's signed grant authorises a machine, and that route stays owner-only for a
  controller too, so even a computer already authorised cannot use a scan to authorise another.
- **Only a genuine, fresh offer is held**: signed by the key its identifier names, within the
  offer's five-minute window. Anything else is refused before it is stored.
- **Bounded**: a body of at most 8 KiB, display strings of at most 80 characters with no control
  characters, 10 requests a minute per caller address, at most 32 waiting at once, one waiting per
  machine (a new offer replaces the old token), and each dropped when its offer expires.
- **Seen by nobody else.** Nothing lists the waiting requests. The only way to read one is to hold
  its token, and what it holds is the computer's public key, what holds that key, the origin and two
  display strings: nothing about the identity.

The Identity Agent does not check that `agent_origin` is its own address (behind a URL relay it
cannot reliably know it). It does not need to: a request naming somewhere else produces a pointer to
somewhere else, which either does not resolve or is refused by the owner's Identity Agent because it
was not served where it says it is for.

### The token

128 random bits, written as 22 characters of unpadded base64url, so the pointer is the origin plus 25
characters. It is unguessable, it is used once (the owner's grant of that machine retires it), and it
expires with the offer. It is held in memory: a restart drops waiting requests, and the computer
shows a new code, which is the same thing the person does when one expires.

### What the Ask carries

`v` (`ASK1`), `t` (8), the six signed fields of the offer (`aid`, `public_key`, `protected_by`,
`agent_origin`, `timestamp`, `signature`; `protected_by` is a label and is not among the signed
bytes), `expiry`, and two display strings, `label` (what the computer suggests calling itself) and
`org_name`. The last three are unsigned, as they were in the device code. `expiry` may only shorten
the offer's window: the owner's Identity Agent refuses one later than the offer's time plus five
minutes. Nothing displayed is trusted for anything, and the person names the machine.

### Expiry and renewal

The code lasts as long as the offer inside it, five minutes from when the computer signed it. The
answer to `POST /api/controller/requests` says when (`expires_at`), and the computer's screen shows
it, says plainly once it has passed, and offers a new code. A new code is a new offer and a new
token, and the old one stops working. Nothing refreshes a code by itself unless a screen chooses to;
the default is that it does not.

### One exchange with sign-in, not a look-alike

The same pointer shape on the same `/i/` route; the same fetch and size limit; the same `ASK1`
envelope dispatched by `t` through the one Ask registry; the same expiry check before any screen;
the same consent binding, which refuses to act on bytes other than the ones the person saw. Two
things differ, each because the parties differ, not because the protocol does:

- **How the asker is authenticated.** A sign-in's site has a key log, and its Ask is checked against
  the key that log puts in force. A computer is named by its key and publishes no key log (ADR-006,
  a controller), so its Ask is checked against the key its identifier is. Both are the asker's own
  signature over what is shown; neither trusts the address it was fetched from alone.
- **Where the answer goes.** A sign-in's answer is a signed assertion posted to the site. This one's
  answer is a grant, which only the owner may make, so it goes to the Identity Agent as the owner's
  own signed request rather than being made by whatever executed the scan.

### The device code during the transition

No implementation outside the reference one has shipped this code, so it is withdrawn now as what a
computer shows (the client marks `toScannableLink` deprecated). Reading it (`ControllerOffer.parse`,
`POST /api/controller/verify-offer`) stays only until the applications that show and read it have
moved to the pointer, and is removed in the change after that. Nothing new may emit it.

### The other device codes

`pair`, `rent` and `adopt` are not changed here. `rent` and `adopt` are links a web page returns to
the person's own application, not codes one device shows another. `pair` is the closest case: a
computer shows it to be claimed, and whether it can become a pointer in the same way depends on
whether an unclaimed machine has an address the claiming device can reach. That is examined on its
own.

### Is this the permanent answer?

- **Not a stopgap.** It removes a second exchange rather than adding one, and every later code a
  device shows can take the same path: leave a signed Ask where both sides can reach it, show the
  pointer.
- **Our own protocol already had the answer.** The Ask, its pointer and its scan gate are the
  protocol's universal interaction path (ADR-021); this puts the controller offer on it. The trust in
  the offer is the computer's own hardware-held key, as before; the authority is the owner's signed
  grant, as before.
- **Standard mechanisms.** A short pointer to a signed document fetched over https is the pattern
  ADR-021 already follows, and the same pattern OAuth device authorisation and OpenID4VP's
  `request_uri` use: keep the code small and put the signed request behind it.
- **What it rests on.** The Identity Agent the computer asks must be reachable from the owner's
  device. That is already true wherever the computer could act for it at all.
