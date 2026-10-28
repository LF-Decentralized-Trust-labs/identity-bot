# Contracts

The formats another implementation has to speak to work with this one. Each is
held to the Go code by a test, so a change on one side without the other fails
here before it reaches anybody else.

## AI agents

| File | What it is |
|---|---|
| `asset-grants/*.schema.json` | The credential schemas an AI agent's authority rests on (ADR-045): the AI Agent Grant (what it may do), the AI Agent Body (which machine key speaks as it) and the Controller Grant (which machine may act for an identity). Each file is the schema byte for byte, so its Blake3 digest is the `$id` it carries and the `s` a credential names. Both versions of each are published, because credentials issued under either can be presented. |
| `agent-body/agent-body.schema.json` | How a machine becomes an AI agent's body and signs as it (ADR-046): the enrolment string, the strings the machine's key signs, the six words a person compares, and the grades. Worked examples: `../agentbody/body-vectors.json`. |
| `agent-message/agent-message.schema.json` | A message between AI agents (ADR-047): what a body signs, the record the Identity Agent countersigns, and how entries chain. Worked examples, including a countersigned two-entry conversation: `../agentmessage/message-vectors.json`. |
| `conversation-bundle/conversation-bundle.schema.json` | An exported conversation, `IA-CONVERSATION-BUNDLE-V1`, which anybody can check offline. The reference checker is `../cmd/verify-conversation`. |

A credential built from an asset grant schema is honoured only when the request
that authorised it holds: it is signed by who it says over the exact string
kept, a machine's request is signed by the key its Controller Grant names and
that grant is the one the credential's edge names, what was asked for is what
was issued, and the grant was in force and unrevoked when the request was made
and before the credential was issued. The check is `authorisation.Check`.

The vector files ship inside the Go module, beside the code that produces
them, so a Go implementation reads the same file rather than a copy. When a
format changes on purpose, regenerate them with
`IA_WRITE_CONTRACTS=1 go test ./schemas ./agentbody ./agentmessage` and review
the diff: every changed line is a change another implementation has to make.

## Elsewhere

| File | What it is |
|---|---|
| `relay/relay-admission.schema.json` | The URL relay protocol's admission messages (ADR-048) |
| `signing/README.md` | The one form every service-provider request is signed over (ADR-049) |
| `backup-format/iab-format.schema.json` | The backup file's manifest |
| `backup-push/push-protocol.schema.json` | Pushing a backup to a paired device |
| `link-verifier/link-verifier-sdk.schema.json` | Verifying a link |
| `root-aid-continuity/continuity-proof.schema.json` | Proving a root identifier continues |
| `update-manifest/manifest.schema.json` | A signed release manifest |
