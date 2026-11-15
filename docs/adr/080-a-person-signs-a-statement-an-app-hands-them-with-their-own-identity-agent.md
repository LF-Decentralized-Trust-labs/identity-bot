# ADR-080: A Person Signs a Statement an App Hands Them, with Their Own Identity Agent

**Status:** Proposed (2026-11-15)
**Date:** 2026-11-15
**Deciders:** to be decided; Ask action 6 is public wire once this ships, and it is the first Ask answered with a root-key signature
**Builds on:** ADR-021 (the Ask), ADR-066 (a browser key speaks for the person who signed in), the root key rule that a person's root key is held only by the device it was made on

---

## Context

An app (for example a task console) sometimes needs proof that a particular person said a particular thing: that
they approve a decision, or disagree with one. A signed-in browser cannot give it: its session says who signed in,
never what that person has now read and agreed to. The proof has to be the person's own Identity Agent's signature,
made with the key that is theirs, after they read the exact words on their own device.

## Decision

1. **A new action, 6 (`sign_statement`).** Code 5 stays reserved as `issue` (ADR-021). A signed-in page calls `session.signStatement(text, {title?})` on the login SDK's session. The SDK asks the app's own back end (`POST /session/statement`, with the session and the browser key's proof, like every call), which has the organisation's Identity Agent start the Ask as the app. The back end keeps the secret that releases the answer; the page is shown a pointer and a wait screen the SDK owns, reads the state (`GET /session/statement/{id}`), and is handed `{signature, signer_aid, kel_sn}` once, only by the session that asked. The Identity Agent's public sign-in route does not start a statement: there a page's `Origin` header is the only proof of who asks, and a script can set it.
2. **The person's Identity Agent signs.** Scanned or pasted, the Ask is fetched, the asker is verified from its key
   log, the statement is checked, and the person sees it exactly, who is asking, and chooses. On yes the device signs the
   envelope in [statement-signature.md](../statement-signature.md) with the root key in force and posts it to the asker.
   A device that does not hold the root key says so in plain words and offers nothing to sign.
3. **The format is open** with byte-exact vectors, so anyone who builds a statement or checks a signature gets the same
   bytes (`identity-agent-core/statements`).
4. **Who may start one:** only an app whose grant holds the capability `app.statement.ask` (held to that one app, approved by the owner on their device), through its back end for a signed-in session. The person's own Identity Agent cannot check the grant (it is the asker's), so it treats every asker as unproven beyond its identifier.

## Trust model

Code 6 is the first Ask whose answer is a root-key signature over text somebody else chose. Any app that may start one
can ask a person for a root-key signature over text it picked. `login/ask_sign.go`'s rule that an Ask is never signed with
the root key is about the asker's own Ask, not the person's answer, and stays.

Why it is safe enough, in order of weight:

1. **The person reads exactly what is signed.** The screen shows the statement verbatim and, for a registered form,
   a reading built only from the checked statement and a checked title.
2. **Consent every time.** No automatic tier. The approval is bound to the exact bytes of the Ask by the consent digest.
3. **The asker is named by its identifier, which is verified** from its key log (the Ask must be signed by the site it names) and which the signed bytes name. The page's name beside it is the asker's own word, and the screen says so, and says whether this person has dealt with that identifier before (a sign-in to an app makes the app a contact).
4. **The signed bytes name the asker**, so the signature is useless to another verifier.
5. **A header no key event can begin with**, so it is never read as a key event or a credential.
6. **Limits on size and characters**, so what is shown is what is signed.

Residual risk, said plainly: a person who approves an attractive statement from an asker they trust has signed it. These
defences make the screen truthful; they do not make the person right. A web page's script can ask for any text;
the protection is on the person's side, not in a rule about who may phrase the request.

## What a valid signature does not show

That the person understood what they signed. It shows that their root key signed those bytes, naming that asker,
after their Identity Agent showed them the statement and they chose to.

## Consequences

- Replays are bounded by the app, not the envelope: a statement says what it is for, and an app counts an identical
  re-posted signature once.
- The asker's half is in memory only. An Identity Agent that restarts forgets an open request, and the page offers to ask again.
- Anyone who can fetch the pointer (it is public at `/i/{token}`) can post an answer with a valid signature of their own key, and so end the wait with a signature the app will refuse; the person then asks again. The asker cannot tell whose signature is whose, so this is a limit, not a defence.
- Any signed-in session of an app may start one; whether it should be only the owner's is the app's to decide (a follow-up).
- A decline is advisory: it is told to the page so it can say so, and only a signature settles the request.
- A person with their root key on a phone, and an Ask opened on a computer that does not hold it, must open it on the phone.
  The phone signs too (the core's handler is in every build, not an add-on), by the supervisor's ruling of 2026-11-15 under the rule that a capability lands on every platform it applies to; Rob's question stays open. A queue the phone fulfils later (`signing_requests`) is separate work.
