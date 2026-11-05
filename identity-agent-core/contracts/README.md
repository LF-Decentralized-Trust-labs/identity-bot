# Contracts

The formats another implementation has to speak to work with this one. Each is
held to the Go code by a test, so a change on one side without the other fails
here before it reaches anybody else.

## AI agents

| File | What it is |
|---|---|
| `asset-grants/*.schema.json` | The credential schemas an AI agent's authority rests on (ADR-045): the AI Agent Grant (what it may do), the AI Agent Body (which machine key speaks as it), the Controller Grant (which machine may act for an identity), and, for an app (ADR-045, amendment of 2026-11-02), the App Grant (what it may ask of the Identity Agent) and the App Body (which machine key speaks as it). Each file is the schema byte for byte, so its Blake3 digest is the `$id` it carries and the `s` a credential names. Every version this code builds is published (1.0.0, 1.1.0 and 1.2.0 of the AI Agent Grant, 1.0.0 and 1.1.0 of the AI Agent Body, 1.1.0 of the Controller Grant, the App Grant and the App Body), because a credential issued under any of them can be presented. |
| `../authorisation/ai-agent-body-request-vectors.json` | Worked examples of a grant for an AI agent that another AI agent created, which rests on a request the creator's body signed (ADR-045, Amendment 3): accepted and refused, each refusal breaking one rule, including that a created AI agent is never more powerful than its creator. Checked independently by `check_ai_agent_body_request_vectors.py`, which needs the `blake3` module |
| `agent-body/agent-body.schema.json` | How a machine becomes an AI agent's body and signs as it (ADR-046): the enrolment string, the sealed enrolment request, the strings the machine's key signs, the approval request a machine shows to be approved (ADR-059), and the grades. Worked examples: `../agentbody/body-vectors.json`. |
| `agent-message/agent-message.schema.json` | A message between AI agents (ADR-047): what a body signs (including an ask's optional tier, `IA-AGENT-MSG-V2`), the record the Identity Agent countersigns, and how entries chain. Worked examples, including a countersigned two-entry conversation and a person's message, in the form written now and the nested form older records hold: `../agentmessage/message-vectors.json`. |
| `model-call/model-call.schema.json` | How an AI agent's body makes its brain's model calls through the Identity Agent that keeps the API key (ADR-057): borrowing the sign-in and the run's lease, the request that starts a call, the answer collected in parts, the refusals and their statuses, the rules for which paths, query parameters and headers a call may carry, and, under an allowance, the rules on answer length and number of answers. A provider's own routes, headers, query parameters and answer-length fields are a profile the Identity Agent lists, read by those rules. Package `modelcall` is the one implementation of these checks, for a body and an Identity Agent alike. Worked examples, allowed and refused, against a made-up example profile: `../modelcall/model-call-vectors.json`, checked independently by `check_model_call_vectors.py`, which needs only the Python standard library. |
| `app-manifest/app-manifest.schema.json` | The manifest of an app beside an Identity Agent (ADR-012, Amendment 5): the rows it declares (name, release, resources, encrypted machine, store, placement, front end and back end, secrets, behaviour when down, backup, outbound hosts) and the exact rule of each. `appmanifest.DecodeManifest` and `appmanifest.Validate` are the check, and a test runs every vector through the schema itself. Worked examples, accepted and refused, each refusal breaking one rule: `../appmanifest/app-manifest-vectors.json`, checked independently by `check_app_manifest_vectors.py`, which needs only the Python standard library. |
| `../endpointrecord/endpoint-record-vectors.json` | A signed endpoint record (ADR-062): the five strings, the bytes the signature is over, which records verify and why not (a record checked against a key other than the one that signed it, including the key a rotation replaced and the one it put in force, a future issue time, an origin out of its one spelling; a record has no age limit, and one vector shows the optional limit a verifier may set), the origins and addresses and their one spelling, which record replaces which, and the strings a controller signs for a request naming its origin (`IA-CONTROLLER-REQ-V3`, and the second form beside it). The vectors carry no key log: they give the key to check against, so following a rotation through a log is tested by the server tests and not by them. Checked independently by `../endpointrecord/check_endpoint_record_vectors.py`, which needs the Python `cryptography` module; Dart reads the same file in `packages/agent_client`. |
| `conversation-bundle/conversation-bundle.schema.json` | An exported conversation, `IA-CONVERSATION-BUNDLE-V1`, which anybody can check offline. The reference checker is `../cmd/verify-conversation`. A genuine export of a seven-message conversation to test a checker against: `conversation-bundle/genuine-bundle.json`; it must verify against its own root, and any change to what it proves must not. |

A credential built from an asset grant schema is honoured only when the request
that authorised it holds: it is signed by who it says over the exact string
kept, a machine's request is signed by the key its Controller Grant names and
that grant is the one the credential's edge names, what was asked for is what
was issued, and the grant was in force and unrevoked when the request was made
and before the credential was issued. The check is `authorisation.Check`.

The vector files ship inside the Go module, beside the code that produces
them, so a Go implementation reads the same file rather than a copy. Keys the
vectors need beyond a body's signing key come from published seeds, each key
from its own: Ed25519 from its 32-byte seed (RFC 8032), ML-DSA-65 from its
32-byte seed (FIPS 204), ML-KEM-768 from its 64-byte seed (FIPS 203), and
X25519 with the 32-byte seed as its private key (RFC 7748). Everything is then
reproducible except a sealed enrolment and a P-256 signature, which draw fresh
randomness and are published as given.

`check_ai_agent_vectors.py` is a second implementation, in Python, written from
the schemas' prose rather than from the Go code. The Go tests run it over both
vector files where Python and its `blake3` module are installed, so prose that
stops describing the code fails a test. Where they are not installed the check
is skipped, unless `IA_REQUIRE_INDEPENDENT_CHECK=1` is set: then a check that
cannot run fails. The relay protocol's Python check and
`check_model_call_vectors.py`, `check_app_manifest_vectors.py`, `check_ai_agent_body_request_vectors.py` and `check_endpoint_record_vectors.py` (which needs the `cryptography` module) follow the same rule.

When a format changes on purpose, regenerate the files with
`IA_WRITE_CONTRACTS=1 go test ./schemas ./agentbody ./agentmessage ./modelcall ./login ./backup ./authorisation ./endpointrecord` (refused
when `CI` is set) and review the diff: every changed line is a change another
implementation has to make.

## Elsewhere

| File | What it is |
|---|---|
| `relay/relay-admission.schema.json` | The URL relay protocol's admission messages (ADR-048) |
| `signing/README.md` | The one form every service-provider request is signed over (ADR-049) |
| `backup-format/iab-format.schema.json` | The backup file's manifest |
| `backup-push/push-protocol.schema.json` | Pushing a backup to a paired device |
| `link-verifier/link-verifier-sdk.schema.json` | Verifying a link |
| `../../packages/login-verify/test-vectors/core-canonical-and-spellings.json` | How the core reads a login: canonical challenge and assertion bodies, which key, identifier and signature spellings it accepts, and a signed assertion. Recomputed from the core by `../login`, and the TypeScript login verifier is held to it |
| `../backup/identity-key-vectors.json` | How an identity's keys come from its recovery phrase: the BIP39 seed, then SLIP-0010 Ed25519 at m/44'/0'/0'/0'/n' for key n, with SLIP-0010's own vector as an anchor. Checked by `../backup` and by the Dart key manager in `packages/agent_client` |
| `root-aid-continuity/continuity-proof.schema.json` | Proving a root identifier continues |
| `update-manifest/manifest.schema.json` | A signed release manifest |
