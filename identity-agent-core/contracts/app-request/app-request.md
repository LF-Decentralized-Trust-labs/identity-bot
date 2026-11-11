# An app's back end signs as the app (ADR-072)

How an app's back end reaches its owner's Identity Agent: as the app, signed by
the App Body key it was enrolled with (ADR-045 Amendment 1, ADR-046), and never
as a controller. This is the whole of what an Identity Agent checks of such a
request, so another Identity Agent or an app's own library can be written from
it. The form is the one an AI agent's body signs (`../agent-body/`); only who is
admitted differs.

Worked examples, admitted and refused, one rule broken by each:
`../../apprequest/app-request-vectors.json`, checked independently by
`../check_app_request_vectors.py`, which needs the `blake3` module. The Go
reading is `apprequest.Check`.

## The request

Headers, with the values the string below is built from:

| Header | Is |
|---|---|
| `X-IA-Body-Host` | the App Body key's identifier (`host` in the App Body credential) |
| `X-IA-Body-For` | the identifier of the Identity Agent the request is for |
| `X-IA-Body-Timestamp` | RFC 3339 |
| `X-IA-Body-Nonce` | at least 16 characters, different for every request |
| `X-IA-Body-Sig` | the signature, in the CESR form a body uses |
| `X-IA-Body-Work-Item`, `X-IA-Body-Reason`, `X-IA-Session` | the stated purpose and the caller's own session; empty when absent. Signed, so nothing between can change them |

The key signs eleven lines joined by a line feed (`IA-BODY-REQ-V3`): that tag;
the Identity Agent; the host; the method in capitals; the request target exactly
as sent, path and query; the timestamp; the nonce; the Blake3-256 digest (CESR
`E`) of the body, which is of zero bytes for a request with none; the work item;
the reason; the session.

## What the Identity Agent checks, in this order

The first refusal is the answer. Each has a `refused` code in the vectors.

1. `names_no_identity_agent`, `other_identity_agent`: the request names this Identity Agent.
2. `unreadable_time`, `outside_window`: the timestamp reads, and is within two minutes of the Identity Agent's clock, either side.
3. `bad_nonce`: the nonce has at least 16 characters.
4. `key_is_not_the_app_bodys`: the host is the one an App Body credential names. Which credential: the one in force, held by an app of this Identity Agent and issued by it. A revoked one names no key.
5. `bad_signature`: the host is derived from the same key as the App Body's `verkey`, and the signature over the string is that key's.
6. `app_body_lapsed`, `app_grant_lapsed`: neither the App Body nor the app's App Grant has passed its `valid_until`. The App Grant is the newest the app holds: if that one is revoked the app has none.
7. `capability_not_held`: the App Grant's `capabilities` hold the one the route needs.
8. `outside_the_grants_limit`, `limit_the_route_cannot_check`: where the App Grant's `resource_constraints` limit that capability, each limited argument is held to the route. The route gives a value for the argument (for `agent.message.send`, `to` is the identifier the AI agent in the path is addressed by, its `pairwise_aid`, which is what a person's statement names it by (see the trail contract), never the asset id the path carries; a path that names no AI agent with such an identifier gives no value) and it is one the grant lists; a limit on an argument the route does not give refuses the request, because a limit that cannot be checked is not read as no limit. Limits on other capabilities do not apply. The vectors carry `grant_constraints` (the limit on the needed capability, per argument) and `route_arguments` (what the route gives), both absent when there is no limit.

Then, outside the vectors because they are the Identity Agent's own state, a
signature is accepted once (a request sent twice is refused the second time),
and the route must be one an app may use.

## Which routes

An Identity Agent lists the routes an app may use, each with the capability it
needs. This one lists the route that carries a person's words (ADR-066, ADR-067):

| Route | Capability | Limit it is held to |
|---|---|---|
| `POST /api/mcp/agents/{id}/conversations` | `agent.message.send` | `to` is the AI agent's `pairwise_aid`, not the `{id}` the path carries |

Reads of a conversation are not listed: they carry no person's statement, so an
add-on lists them only once it scopes a read to a person.

An add-on lists its own with the same meaning: the capability, and which part of the route gives each argument a grant may limit. An app is held to its request rate on every one. **Every other route refuses the
key**: a route a controller may use, and a route only the owner's own keys may
use. An app holds no key that speaks for any identity (ADR-072 section 4), so
no score and no signer applies to it. A request that also carries a controller's
or the owner's signature, or a token, is refused, not read as either.

## A person's words

On the route that carries a person's words to an AI agent, the app's signature
is not enough. The request also carries the person's own signed statement
(ADR-067), in three headers: `X-IA-Speaking-For` (the person's identifier at the
app), `X-IA-Person-Statement` (base64url of the statement and the key and
signature that signed it) and `X-IA-Person-Salt` (base64url). All three are
needed. They are not under the app's signature: the statement names the words,
conversation, recipient and message it is for, is signed by the person's own key
and is accepted once, so what the headers carry cannot be swapped for another
person's, or for other words.

## What is kept

The person's statement is kept with the entry as the proof of what was asked,
and not the signed string, its signature or the body, which hold the person's
words (ADR-068). The App Body credential that names the key is
carried with a conversation bundle (`../agent-message/` `controller_proof.app_body`),
so anybody can check offline which app's machine carried a person's statement.
Whether the app's grant held the capability is the Identity Agent's decision
when it took the request; a bundle does not show it.

## What this does not settle

The front end's own signed requests, sealing between a front end and its back
end, the sign-in challenge's front-end kind and an app's approval request for one
action are ADR-072's, and are specified when they are built.
