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
