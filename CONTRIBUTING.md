# Contributing to the Identity Agent

Thank you for helping. This page says how a change reaches `main`. Some of these
requirements are enforced by GitHub; the rest are the project's own, and maintainers
hold every pull request to all of them.

## How a change reaches `main`

1. **Work on a branch and open a pull request.** Nothing is pushed to `main` directly.
   Cut your branch from the current `main`, and keep one pull request to changes that
   would be undone together.
2. **Sign off every commit** (enforced). The project uses the
   [Developer Certificate of Origin](https://developercertificate.org/). Commit with
   `git commit -s`, which adds a line like
   `Signed-off-by: Your Name <you@example.com>`. The email must be in angle brackets.
   The DCO check fails a pull request with any commit missing it.
3. **Every check must be green** (project requirement). The *Core — builds everywhere*
   workflow builds the Go core for every system it runs on, type-checks it for the
   phones, and runs its tests. A pull request with a red check is not merged, even
   though GitHub does not block the button.
4. **One review by someone other than the author** (project requirement). The reviewer
   reads the diff and checks the description's claims against the code. An author
   never merges their own unreviewed pull request.
5. **Fill in the pull request template.** It asks for a short summary, what changed,
   where it lands, why, who outside the project it helps, and how it was tested.
   "The tests pass" alone is not evidence: name the case that would have failed
   before the change.

## Platforms

A change lands on every platform it applies to, in the same pull request. Write the
code for a platform you cannot test on, and say in the pull request that it is
untested there.

| Where it runs | Systems |
|---|---|
| Desktop app | macOS, Windows |
| Phones (apps that embed the core) | iOS, Android |
| Servers (the sealed server image, agent-host on AI agent machines) | Linux |

A Linux desktop app is incomplete and deferred: it remains a goal and is open to
contributions, but is not currently maintained. The Linux builds in CI are for the
server targets.

## Security

Never report a vulnerability in an issue or pull request. See
[SECURITY.md](SECURITY.md).
