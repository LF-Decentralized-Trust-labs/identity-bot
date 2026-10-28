# Contributing to the Identity Agent

Thank you for helping. This page says how a change reaches `main`. GitHub enforces
only the sign-off. The other requirements are the project's own: GitHub does not
block a merge without them, so maintainers check them before merging.

## How a change reaches `main`

1. **Work on a branch and open a pull request.** Nothing is pushed to `main` directly.
   Cut your branch from the current `main`, and keep one pull request to changes that
   would be undone together.
2. **Sign off every commit** (enforced). The project uses the
   [Developer Certificate of Origin](https://developercertificate.org/). Commit with
   `git commit -s`, which adds a line like
   `Signed-off-by: Your Name <you@example.com>`. The email must be in angle brackets.
   The DCO check fails a pull request with any commit missing it.
3. **It builds and its tests pass on every supported system** (project requirement).
   Before you open or update a pull request, make sure the Go core builds and vets
   for every system it runs on, type-checks for the phones, and passes its tests
   (commands below). Maintainers check the same before merging, and a pull request
   that fails any of them is not merged.
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
contributions, but is not currently maintained. The Linux builds below are for the
server targets.

### Checking a change on every system

From `identity-agent-core`, with the Go release named in its `go.mod`:

```bash
# Every system the core runs on, cross-compiled with cgo off, and vetted
for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  CGO_ENABLED=0 GOOS=${t%/*} GOARCH=${t#*/} go build ./... &&
  CGO_ENABLED=0 GOOS=${t%/*} GOARCH=${t#*/} go vet ./... || echo "FAILED: $t"
done
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go vet ./...

# The tests, and the wire-protocol modules nested inside the core
go test ./...
for m in relayproto witnessproto; do (cd "$m" && go vet ./... && go test ./...); done

# On a Mac only: the Secure Enclave code (cgo) and iOS against the iPhone SDK
CGO_ENABLED=1 go build ./... && CGO_ENABLED=1 go vet ./...
CGO_ENABLED=1 GOARCH=amd64 go build ./... && CGO_ENABLED=1 GOARCH=amd64 go vet ./...
CGO_ENABLED=1 go vet -tags sepblob ./...
GOOS=ios GOARCH=arm64 CGO_ENABLED=1 CC="xcrun -sdk iphoneos clang -arch arm64" go vet ./...
```

If you cannot run the Mac part, say so in the pull request.

## Security

Never report a vulnerability in an issue or pull request. See
[SECURITY.md](SECURITY.md).
