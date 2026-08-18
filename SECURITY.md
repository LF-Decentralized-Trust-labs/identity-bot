# Security Policy

## Reporting a Vulnerability

The Identity Agent project takes security seriously. If you believe you have found a security vulnerability, please report it to us responsibly.

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

### How to report

**Preferred channel — end-to-end encrypted message via your Identity Agent.** If you have an Identity Agent installed and the secure messaging feature is available in your build, send your report as an E2EE message to the project's published Identity Agent address. This is the most secure channel and uses our own technology end-to-end. *(This option becomes generally available when the Identity Agent communications feature ships — track release notes.)*

**Fallback channel — email.** If you do not have an Identity Agent or the messaging feature is not yet available in your build, send an email to **security@antispamguy.org** with:

- A description of the issue and its potential impact
- Steps to reproduce the vulnerability
- The affected version(s), commit hash, or branch
- Any suggested mitigations, if known
- Your name and contact information (optional — reports can be anonymous)

If you prefer encrypted email, request our PGP key in your initial message and we will respond with it.

## Response Timeline

We aim to follow the timeline below for every valid report:

| Stage | Target |
|---|---|
| Acknowledgment of receipt | Within 48 hours |
| Initial triage and severity assessment | Within 7 days |
| Status update cadence during investigation | Weekly, minimum |
| Fix released (or mitigation published) | As soon as practical, in coordination with reporter |
| Public disclosure | Coordinated with reporter; typically after a fix is released |

We follow **coordinated disclosure**: we will work with you on a timeline that protects users while giving you appropriate credit for the finding.

## Scope

### In scope

- The `identity-bot` / Identity Agent source code in this repository
- The bundled Python KERI driver (`drivers/keri-core/`)
- The Flutter UI (`identity_agent_ui/`)
- The Go backend (`identity-agent-core/`)
- The sandbox marketplace runtime (Podman + compiled binary runtimes)
- Official release binaries published by the project

### Out of scope

- Third-party applications installed via the sandbox marketplace (report to the app publisher)
- Issues in upstream dependencies without exploitable impact in the Identity Agent context (report upstream)
- Hypothetical attacks requiring implausible prerequisites (e.g., "attacker has root access to the device already")
- Social engineering attacks against project contributors
- Denial-of-service attacks against the local agent by the user's own device

## Supported Versions

The project is in active development and has not yet reached 1.0. At this stage, security fixes are applied to the `main` branch only. Once we ship a stable release, this section will be updated with a version support matrix.

## Recognition

We credit reporters in release notes and, where appropriate, in a published security advisory — unless you prefer to remain anonymous.

## Governance

This security policy is maintained by the Identity Agent project under the Linux Foundation Decentralized Trust (LFDT). The project follows the LFDT vulnerability disclosure process where applicable.

---

*Last updated: 2026-04-11*
