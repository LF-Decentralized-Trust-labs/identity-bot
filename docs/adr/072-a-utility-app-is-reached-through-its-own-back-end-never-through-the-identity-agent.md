# ADR-072: A Utility App Is Reached Through Its Own Back End, Never Through the Identity Agent

**Status:** Accepted (2026-11-09)
**Date:** 2026-11-09
**Deciders:** Rob Andersen
**Amends:** ADR-066 (its implementation note "A signed-in person speaks to an AI agent from the app's page")
**Builds on:** ADR-006 (no browser reaches the core), ADR-012 Amendment 5 (the rows an app beside an Identity Agent declares), ADR-021 (the Ask), ADR-045 Amendment 1 (an app is an asset with a grant and a body), ADR-048 (the relay)

---

## Context

Two different kinds of software serve one person or organisation, and they must not be confused.

- **The Identity Agent** is the identity. Its core holds the keys and makes every decision about the identity, on a phone or on a machine that can prove what software it runs. It is controlled only from an installed Identity Agent app: the device holding the root identity, or a controller, as ADR-006 defines both. Never from a browser (ADR-006, amended 2026-11-07).
- **A utility app** gives the person a use of their identity. This ADR uses the name for what ADR-012 Amendment 5 calls an *app beside an Identity Agent*: a chat app with AI agents, a task tracker, calling, messages, email, or anything anyone writes. It runs on a machine of its own or a shared one, never inside the Identity Agent. It is an asset of an Identity Agent, its **owner's**, with its own identifier, an App Grant, and an App Body: the machine key it runs under (ADR-045 Amendment 1).

### The parts of a utility app, and the configurations it runs in

A utility app has two kinds of part, and this ADR uses these names for them throughout.

- **The back end** holds the app's data and does its work, on the machine the app runs on. It is the part that is enrolled as the app and holds the App Body key.
- **A front end** is the part a person uses. It comes in two kinds:
  - **A browser front end** is a page loaded in a browser.
  - **An installed front end** is the app's own installed app on the person's device. It may also work in the background, for example to ring or notify, when it is not open on screen.

Where the parts run gives four configurations. The protocol in this ADR is the same in all four; only who runs each part differs.

1. **A browser front end hosted by another party.** A page served from a fixed address by someone other than the back end's operator, talking to a back end run by someone else.
2. **A browser front end and back end run by one operator.** The same operator serves the page and runs the back end.
3. **An installed front end with the back end elsewhere.** The installed app is on the person's device and the back end runs on another machine.
4. **An installed front end and back end on one device.** Both run on the person's own device.

A utility app needs a front end a person can use. ADR-012 Amendment 5 already lets an app declare its front ends (`device_front_ends`: `browser` and/or `installed_app`) and where a browser page is served from (`static_front_end_url`). What no ADR has said is how a front end reaches its app, what it may talk to, and who decides which front ends a person may use.

Without that, the shortcut is for the front end to call the Identity Agent core directly. One path does that today. ADR-066's implementation note "A signed-in person speaks to an AI agent from the app's page" lets a page call the core's talk routes with a browser key. The core answers CORS for that app's origin on those routes. ADR-006's 2026-11-07 amendment lists it as one of three places that do not conform yet, "being reworked so that the app asks from its own server". This ADR is the shape it is reworked to.

## Decision

### 1. A front end talks only to its own app's back end

A utility app's front end, whether a browser front end or an installed front end, sends its requests to that app's back end and to nothing else. **It never calls an Identity Agent core, and no core answers a utility app's browser origin.** The back end talks to its owner's Identity Agent as an enrolled app, signed by its App Body key over its own connection.

**Where the core keeps a record as the person's own** (for example, a message the person sends an AI agent), the back end passes the front end's signed request on inside its own signed call, and the core checks both signatures: the app's, and the key the person's sign-in approved. The request reaches the core only through the back end.

**A utility app's front end is never an Identity Agent app.** The Identity Agent app shows only what governs the identity: keys, credentials, grants, revocation, recovery, the governance record, and the universal approval and consent screens. It also lists the person's utility apps, with each one's settings and a way to open it.

### 2. Every front end follows one protocol

The same steps for every utility app, whoever wrote it, for an individual or an organisation:

1. **The page comes from a fixed address.** A browser front end is loaded from the app's `static_front_end_url` (ADR-012 Amendment 5), never through a relay (ADR-048 §12) and never from a core. An installed front end is the app's own installed app, which may also work in the background.
2. **The link names the app.** A person opens the app from a link or code carrying the app's identifier. The front end fetches that identifier's key log and the app's App Body credential, checks that the credential has not been revoked, and from then on accepts answers only when they are signed by the machine key that credential names. Whoever carries the traffic cannot substitute another app.
3. **The front end makes a key it cannot export.** A browser makes one per ADR-066. An installed app makes one in the device's secure hardware.
4. **Sign-in is the Ask** (ADR-021). The owner's Identity Agent issues the challenge for the app, naming the front end's key (as ADR-066's `browser_key` does) and its kind: `browser` for a browser front end, `installed_app` for an installed front end. The person approves on their own Identity Agent app, and the signed assertion repeats the key. The back end then binds the person to that key: a **session** for a browser, or an **app-key grant** for an installed app, the installed counterpart of a session, which lasts until it is revoked.
5. **Every request after that is signed by the front end's key** over its method, target, a hash of its body, the app's identifier, the session, a timestamp and a nonce. It is **sealed for the app's back end**, and every answer is signed by the App Body key and sealed for the front end's key. The app's machine opens no port, so the traffic passes through a relay (ADR-048), which carries ciphertext only.

### 3. Which front ends an app may be reached by is a setting per app

An app declares the front ends it offers in `device_front_ends`. Some apps will only ever have one: a phone dialler is an installed app, and a dashboard may be a page. Many have both. **The app's owner may switch off any front end the app offers, and cannot switch on one it does not offer.** The owner's Identity Agent enforces the setting when it issues a sign-in challenge for the app. It refuses one whose front-end kind is not offered or is switched off, and gives the reason. The app's back end is never trusted to enforce this, because an app that has been broken into would ignore it.

For an individual, the owner and the person signing in are the same, and so are their Identity Agents. For an organisation's app they differ: the organisation's Identity Agent holds the app, keeps its connection and enforces the setting, while each person approves on their own Identity Agent.

### 4. No utility app controls an Identity Agent

**A utility app never controls an identity: it is a third-party app anyone can write. Anything that manages an identity, which is anything owner-only, is done only by a designated Identity Agent controller app. A utility app is everything that uses the identity.** The core therefore refuses an app's key on every owner-only route and every controller-only route.

A utility app holds no key that speaks for any identity, through any front end. When it needs something only its owner's Identity Agent can give (a capability call, its data key, a request sent with a stored credential), its back end asks over its own connection, signed by its App Body key. The Identity Agent grants or refuses, and records the answer.

### 5. An action that needs consent is approved on an Identity Agent app

When an app needs the person to approve one specific action, such as sending a payment or adding a contact, its back end sends the request as **structured fields** naming that action, signed by its App Body key. The person sees it on their Identity Agent app's consent screen, in that screen's fixed layout, and their signed answer is bound to the exact fields shown. The app never supplies a layout, markup or code. The name shown for the app comes from its asset record, never from a name the app supplies about itself.

### 6. Revocation is immediate

When the owner revokes an app, or one front end of it, the owner's Identity Agent tells the app's back end over its connection. The back end ends every session and app-key grant at once.

```mermaid
sequenceDiagram
  autonumber
  actor P as The person
  participant FE as Utility app front end - a browser front end or an installed front end
  participant R as Relay, a provider treated as untrusted
  participant B as Utility app back end, on its own machine
  participant OIA as The app owner's Identity Agent core
  participant PH as The person's own Identity Agent app

  Note over FE,B: Every message between the front end and the back end passes through the relay, sealed. It is drawn once.
  Note over PH: The person's own Identity Agent app and the core behind it, drawn as one. For an individual's app it is the owner's.
  B->>R: dials out and claims the app's relay name, no open port
  B->>OIA: keeps one connection open, signed by its App Body key
  P->>FE: opens the app from its link or code, which names the app's identifier
  FE->>R: fetch the app's key log and App Body credential
  R->>B: passed on
  B-->>FE: key log and credential, checked against the identifier in the link
  FE->>FE: makes a key that cannot be exported
  FE->>B: sign-in request naming its key and its kind
  B->>OIA: asks for a sign-in challenge naming the front end's key and kind
  OIA->>OIA: is this kind offered by the app and allowed by its owner
  alt that kind is switched off
    OIA-->>B: refused, with the reason
    B-->>FE: refused, this app is not reachable this way
  else allowed
    OIA-->>B: the challenge, naming the front end's key
    B-->>FE: the challenge, shown as a code
    P->>PH: scans the code, sees the app's recorded name, approves
    PH->>OIA: signed assertion repeating the front end's key
    OIA-->>B: the assertion, checked
    B-->>FE: a session or an app-key grant, bound to that key
  end
  loop every request
    FE->>B: request signed by the front end's key, sealed for the app
    B->>B: checks signature, time and nonce, does the work in its own store
    B-->>FE: answer signed by the App Body key, sealed for the front end's key
  end
  opt the core keeps the record as the person's own
    B->>OIA: the front end's signed request, inside the app's own signed call
    OIA-->>B: both signatures checked, recorded
  end
  opt the action needs the person's consent
    B->>OIA: an approval request for that exact action, as structured fields
    OIA->>PH: the consent screen - the action in words, the app's recorded name
    P->>PH: approves or refuses
    PH->>OIA: answer, signed, bound to the exact fields shown
    OIA-->>B: the signed answer
  end
  Note over PH,OIA: later, the app's owner, on their own Identity Agent app
  PH->>OIA: revoke this app or this front end
  OIA->>B: revocation, over its connection
  B->>B: ends every session and app-key grant at once
```

## Consequences

- **One way in for every app.** A developer writing a utility app builds against this protocol and needs nothing from an Identity Agent's routes except the sign-in Ask and the app's own connection.
- **The core's surface does not grow per app.** No core serves an app's page or answers an app's browser origin. The talk-route path ADR-066 described moves behind the app's back end: the core stops answering the app's origin there and admits the person's signed request only inside the app's own call.
- **An Identity Agent is the control point, never the data path.** It approves sign-ins, enforces which front ends an app may use, answers the app's requests and asks for consent. The app's own traffic does not pass through it.
- **ADR-006's other two non-conforming places are not settled here.** The app display at `/apps/{app_id}/` and `/sandbox/llm/v1` belong to the older sandboxed-app kind. This ADR covers only apps beside an Identity Agent, so they stay listed in ADR-006 until they are reworked.
- **Stated weaknesses.** The relay is a provider the person did not choose to trust. It reads nothing, but it sees that somebody reached the app and when, and it can refuse to carry traffic. On phones whose operating system wakes a closed app only through the platform's push service, an app that must ring or notify has to send a sealed wake-up through that service. The wake-up carries nothing readable, but on that platform it is a dependency the person cannot avoid.

## What this does not settle

- **The client library.** A library implementing this protocol for browser pages and installed apps belongs beside the formats it implements. This ADR fixes the protocol, not the library.
- **Wire formats**, with test vectors, for: the owner's setting (its routes are built, Amendment 2); the sealing of front-end traffic; the back end's call carrying a front end's signed request; and an app's approval request for one action. Each is set when it is built.

## What is built

**Built:**
- the Ask (ADR-021)
- the browser key in a challenge and an assertion (ADR-066)
- the app manifest's `device_front_ends` and `static_front_end_url` (ADR-012 Amendment 5)
- the relay for an Identity Agent (ADR-048)
- the App Grant and App Body formats (ADR-045 Amendment 1); the App Grant is issued by `ProvisionAppAsset`, which no route calls yet
- an app's back end signing as the app, with its App Body key, to the routes an app may use (Amendment 1)
- the front-end kind in a challenge and an assertion, with test vectors (Amendment 2)
- the owner's setting of which front ends an app offers may be used through, and its enforcement when a sign-in starts and again when it is approved (Amendment 2)
- sealed front-end traffic: the format, test vectors, the page's side and the Go side (Amendment 4); the add-ons' back end and AI Chat's side are built in their own repositories

**Not built:**
- a front end checking the app's key log and App Body credential
- an installed front end's hardware key and its app-key grant
- an app claiming its own relay name
- the back end carrying a front end's signed request to the core
- an app's approval request for one action
- revocation pushed to the app

The talk-route path that ADR-066 describes is built, and conforms to this ADR as of Amendment 1.

## Amendment 1 (2026-11-10): how an app's back end signs as the app

*Amended 2026-11-10. This settles what section 4 and section 1 left open for the talk routes, which an earlier change had built with the app's machine as a controller. The amendment is this section and three edits above it, each made by it: the bold sentence that opens section 4, the new last line of the Built list, and the closing line of "What is built", which no longer says the talk-route path does not conform. Nothing else above is changed.*

**The request.** An app's back end signs each request to its owner's Identity Agent with its App Body key (ADR-045 Amendment 1), in the form an AI agent's body signs (ADR-046, `IA-BODY-REQ-V3`, headers `X-IA-Body-*`). The format, what the Identity Agent checks and the order it checks it in are published as a contract with vectors and an independent checker: `identity-agent-core/contracts/app-request/app-request.md`. The key is the one an App Body credential in force names, held by an app of this Identity Agent, and the app holds an App Grant in force that holds the capability the route needs.

**Which routes.** An app may use only the routes the core lists for it, and an add-on may list its own (`Addon.AppRoutes`). The core lists the one route that carries a person's words, `POST /api/mcp/agents/{id}/conversations`, which needs `agent.message.send`. Where the app's App Grant limits that capability (`resource_constraints`), the limit on `to` is held to the AI agent in the path, by the identifier its entries are addressed to (its `pairwise_aid`, as a person's statement names it) and never by the asset id: an app limited to one AI agent cannot post to another's route. A grant that limits an argument the route does not give is refused on that route, because a limit that cannot be checked is not read as none (`contracts/app-request/app-request.md`, refusal 8). An add-on lists the argument each of its routes gives, so its own limits are held the same way, and an app is held to its request rate on every route it may use. Reads of a conversation are not listed until a read is scoped to a person. Every other route refuses an app's key: every route a controller may use, and every owner-only one. No score and no signer is involved, because an app is neither.

**A person's words.** The person-statement rule of ADR-067 is unchanged: on the route that carries a person's words, a request is accepted only with the person's own signed statement beside the app's signature (`X-IA-Speaking-For`, `X-IA-Person-Statement`, `X-IA-Person-Salt`). The app's signature covers the request, not those three headers; the statement names the words, conversation, recipient and message it is for, is signed by the person's own key and is spent once.

**What the record keeps.** The person's statement is kept as the proof of what was asked, never the app's signed request, which holds their words (ADR-068), with the App Body credential that names the app's key (`ControllerProof.AppBody`), so a conversation bundle shows which app's machine carried the person's statement by a credential anybody can check. A controller's request is kept as before.

**Controller Grant 1.2.0.** An app is not a controller, so its `app_asset` is not written and not honoured. Nothing binds a machine to an app. The schema stays published, byte for byte, so a credential issued under it still reads; a later version may drop the field. The path arrived in #436, three merges before this change, and is not known to have reached any outside adopter, so none is taken to hold such a credential or such a record; if one does, this is the call that is wrong for them, and it is reversed by reading their entries in `checkPersonSpoke` as before. Three consequences, each decided:

- *The credentials are withdrawn.* A machine recorded as bound to an app stops standing (`ControllerGrant.Live`), and at start-up the Identity Agent removes each one and withdraws its Controller Grant in the registry, once (`withdrawTheGrantsOfRetiredAppBackEnds`), so no credential still shows it in force. Where the key is on another device the withdrawal is queued for it, as for any machine its owner removes.
- *The records fault.* A conversation entry made through such a machine, a controller's request with a person's statement under a Controller Grant that names `app_asset`, now faults in the conversation bundle (`checkPersonSpoke`), as a controller that is no longer one. It is not read as a plain controller's entry and not excused as having been valid when made: no outside adopter is known to hold one, and keeping a second reading of an app's entry alive would keep the controller path this amendment removes. Entries an app signed as the app are read by `checkAppSpoke`.
- *The bundle's name for the app changes meaning.* The conversation bundle's `Message.App` (JSON `app_asset`) was the asset id a Controller Grant named. It is now `Message.AppAID` (JSON `app_aid`): the identifier of the app that holds the App Body credential whose key signed the request. It was renamed rather than kept under the old name, because the old name would have carried a different thing.

**Not settled here.** The sign-in challenge's front-end kind, the owner's per-front-end setting, sealed front-end traffic, an app's approval request for one action, and revocation pushed to the app remain as listed above. An app's key is refused on the routes that serve them until each is built and listed.

## Amendment 2 (2026-11-11): the front-end kind is named in the signed challenge, and what the owner's setting does and does not do yet

*Amended 2026-11-11. This builds the front-end kind in a challenge and the owner's per-front-end setting that section 2 step 4 and section 3 left to be built. Edits above, each made by this amendment: two lines moved from "Not built" to "Built", and the wire-formats line of "What this does not settle". Nothing else above is changed.*

**The kind is in the signed challenge and repeated in the assertion.** A challenge for a utility app carries `front_end` (`browser` or `installed_app`) in its signed body, written between `browser_key` and `callback_url` and left out when the challenge names none, so every other challenge keeps its form. The person's assertion repeats it as `front_end`, the signature covers it, and a verifier refuses an assertion whose kind is not the one the challenge named, or that names one where the challenge named none, with the reason `front end mismatch`. It is checked after the browser key and before the signature. The person's Identity Agent carries the kind in its consent preview; showing it on the consent screen is not built yet, and matters once installed apps can sign in, since an installed_app sign-in is refused until then. Test vectors: `packages/login-verify/test-vectors/verify-decisions.json` (the front-end cases) and `core-canonical-and-spellings.json` (one challenge and one assertion that name a kind), held in Go and TypeScript alike. A challenge with a kind that is not one of the two is refused by the person's Identity Agent before consent.

**A kind is believed only as far as the request backs it.** The kind is what the caller says, and a web page can say anything. So:
- `installed_app` is accepted only when the request carries an installed app's own key. That key (the installed front end's hardware key and its app-key grant) is not built, so until it is, **every `installed_app` sign-in is refused on every route.** Without it an installed-app sign-in is a bearer QR sign-in that nothing tells from a browser's, and a page could call itself the installed app to get round a switched-off browser.
- A request from a web page (it carries a browser `Origin` header), or for a browser's key, is a browser's, and is refused if it names any other kind.

**Older apps.** An app made before it could declare its front ends has no list, and a missing list means *not declared*, never *offers none*: such an app signs people in as it always did. Whether the owner has declared is stored apart from the list, so a declared empty list still refuses every sign-in. The list is set when the app is made or its enrolment token is issued, by the owner and never by the enrolling machine, or when it is provisioned as a delegated app (`ProvisionAppAsset` takes it). For an app that has none, the owner may declare it once, from its manifest's `device_front_ends` (`PUT /api/assets/{id}/front-ends/offered`); a second declaration is refused, because what an app offers is not for the owner's switches to grow. This route and `PUT /api/assets/{id}/front-ends` are the owner's alone, and reading is open to the owner's paired controllers (ADR-050).

**Switching off applies to new sign-ins only, until revocation push exists.** The owner's Identity Agent checks the setting when it issues a challenge and again when the approval completes, so a challenge issued just before the switch cannot be approved after it. A session or app-key grant already open is not ended: section 6's revocation push to the app's back end is not built, so people already signed in stay signed in until they sign out.

**Accepted: the refusal reasons on a public route say what the owner set.** A sign-in is asked for on a public route, and its refusal says that the app does not offer a front end or that its owner has switched it off, so anyone who can reach the route can learn which front ends an app offers and which are off. The front end needs the words to tell the person, and the setting is not a secret from people the app is for.

**Not built, still:** the installed front end's hardware key and app-key grant (the proof `installed_app` waits for), and revocation pushed to the app.

**Accepted for now: an installed app signs in as `browser`.** Until an installed app has a key of its own (above), the installed Flutter apps sign in with a browser key and name the `browser` kind, because `installed_app` is refused on every route. So **switching off "browser" on an app also stops its installed apps, and switching off "installed app" stops nothing yet.** The owner's switch says so in plain words where it is shown. When the installed app's own key is built, installed apps move to `installed_app` and the two switches mean what they say.

## Amendment 4 (2026-11-12): how front-end traffic is sealed, and what the relay still sees

Section 2 step 5 says traffic between a front end and the app's back end is sealed. This sets the format. The test vectors are `packages/login-web/test-vectors/seal.json`; the TypeScript is `packages/login-web/src/seal.ts` and the Go is `packages/login-go/seal.go`, and both reproduce every vector byte for byte.

**The outer call.** Every call is one `POST` to one fixed path, `/sealed`, whose body is `{"v":1,"epk":…,"ct":…}`, and every answer is one `200` whose body is `{"v":1,"n":…,"ct":…}`. Method, route, query, headers, session, proof, status and body are all inside `ct`, so a relay carrying it cannot tell a sign-in from a chat message.

**The seal.** The front end makes a fresh P-256 key for each call (`epk`) and agrees a secret with the back end's sealing key by ECDH. HKDF-SHA256, salted by `epk` then the sealing key, gives the request its AES-256-GCM key and nonce. The answer's are salted by `epk`, the sealing key and `n`, 32 random bytes the back end makes for each answer and carries in it (the page accepts 16 to 32). The answer therefore never depends on `epk` being new: a call answered twice, by a replay that got through or by a restart that forgot, is answered under two different keys. The version, the relay identifier, the direction and `epk` (and, for an answer, `n`) are the associated data, so a call cannot be taken for an answer or for another app's, and a later version cannot relabel these ciphertexts. Every base64url value is read in its one canonical spelling and every field name case-sensitively, in Go, TypeScript and Dart alike: Go's own decoder accepts four spellings of one `epk` (87 characters carry 2 unused bits) and ignores line breaks, which let a relay replay a call past a replay memory keyed on the text. The plaintext is its length (4 bytes), the content, then zeros to a size of 1024 bytes doubling, so size shows only which bucket a message is in. A message may carry 16 MiB at most.

**The sealing key.** The back end's sealing key is derived from the relay identifier's seed, so it is kept nowhere of its own and is the same on every machine the app runs on. The sign-in link carries it as `seal`: the relay identifier's inception, the key, and the identifier's signature over the key. The statement is the identifier's whole signed key log, the key, `sn` (the sequence number of the log's last event) and the signature of the key that log names now over the identifier, `sn` and the key. The page reads the log as it reads an answer's, requires `sn` to be the log's last event, and holds it to the longest log it already knows for the identifier, so a key the identifier has rotated away from vouches for nothing and a statement made earlier is not taken for a later one. The link also carries `min`, `<sequence number>.<SAID>` of the latest event of the relay identifier's key log the owner's Identity Agent has seen (it keeps the longest log the app's machine has reported, and refuses a report that does not carry on from it). The page requires the log it is shown to hold that event at that number, so a browser that has never seen the app, or an installed app that has lost its memory, is not handed a true but earlier log (a removed first machine's, whose key the identifier has since left). The page's own memory of the longest log still applies on top; a memory that cannot be read is replaced by the minimum, and refused where there is none. A link without `seal` or `min` is refused. The sealing key is made from the current key's seed, so a rotation changes it and links made before the rotation stop working. **Links made before this carry none, so they stop working and must be made again.**

**A removed machine that was not destroyed keeps the sealing key.** It is a static key with no forward secrecy: whoever holds it, or later gets the seed, can read every call and answer recorded for this app, past and future, until the relay identifier's key is rotated. Removing a machine that is lost or compromised must therefore be a compromised removal (`Replace`), which rotates the key and so the sealing key; a removal of a machine that was properly destroyed need not. Giving the sealing key a lifetime of its own, rotated whenever a machine is removed, is not built; it is logged as a follow-up to T-1118.

**The signatures travel inside.** The browser's proof (the headers of step 5, unchanged) is part of the sealed call, and the app's signed answer (ADR-072 Amendment 1's `APP-ANSWER-V1`, with the relay identifier's whole key log in place of its inception) is part of the sealed answer. Both are checked after opening, exactly as before. A back end refuses a sealed call whose `epk` (by its decoded bytes, not its spelling) it has seen within the request window, and one dated before it began, so a restart does not reopen the calls it forgot; a call is remembered only once it has opened and is dated well, and in a memory of its own, so what anyone who can reach the relay posts cannot fill it. A call with no session, which carries no proof, is therefore not replayable by the relay either.

**What the relay can still see.** That someone reached the app, and when; the size of each call and answer, to the bucket; the order and spacing of calls, which can suggest what the person is doing; the relay identifier and the relay name; and where the page's request came from, as the relay's own connection tells it. Also the outer status code (a refusal is 400 or 503, not 200); the browser's `Origin` and preflight, `User-Agent` and `Accept-Language`; the size of a large message to within a factor of 2; and that the first call after a page load is the sign-in. It can still refuse to carry a call, delay one, or drop one; the page then says the app could not be reached. It cannot read, alter or swap any call or answer without the page refusing it, and it cannot get a call answered twice: the back end refuses the second, and even an answer made twice is under two keys. It can send a call again and see that the back end refused it.

**Not covered.** The page's own origin and the page code itself are as trusted as the host that serves them. A person's device that is compromised is not helped by this.

**Installed front ends** use the same format with their own key in the proof (their hardware key is still not built, as above). `login-verify` carries no front-end traffic and has no sealing code.
