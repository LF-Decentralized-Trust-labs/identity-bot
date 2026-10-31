# Identity Agent

An open, vendor-neutral implementation of the Identity Agent Protocol: a
user-controlled agent that holds a person's or an organisation's identity, built
on KERI.

This repository is the **core** — a Go program with the KERI engine (`keri-go`)
compiled in, which serves the Identity Agent's HTTP API on a desktop, on a
server, or embedded in a phone app. It ships no app of its own: you build an app
on the core, and `packages/agent_client` is the Dart client for its API.

A downloadable open app that anyone can install is a goal for later.

## What is here

| Path | What it is |
|---|---|
| `identity-agent-core/` | The core: the server, the KERI engine, and `mobilecore`, the package a phone app embeds |
| `packages/agent_client/` | The Dart client for the core's API, for apps built on the core |
| `packages/login-web/`, `packages/login-verify/` | Sign in with an Identity Agent: the website widget, and verification for the service behind it |
| `packages/link-verify-web/` | Link verification for web pages |
| `identity-agent-core/contracts/` | The formats another implementation has to speak to work with this one |
| `sandbox-apps/` | An example app that runs sandboxed inside an Identity Agent |
| `tools/sealed-image/` | Building the sealed server image, and checking its measurement yourself |
| `docs/adr/` | The architecture decisions, numbered and dated |

## Start here

- [BUILDING.md](BUILDING.md) — build the core for macOS, Windows, a Linux server,
  iOS or Android, and build an app on it.
- [CONTRIBUTING.md](CONTRIBUTING.md) — how a change reaches `main`.
- [SECURITY.md](SECURITY.md) — reporting a vulnerability.

## License

See [LICENSE](LICENSE).
