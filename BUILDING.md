# Building the Identity Agent

This repository builds the Identity Agent **core**: a Go program with the KERI
engine (`keri-go`) compiled in, which serves the Identity Agent's HTTP API. It
ships no app. You build the core for the machine it will run on, and build your
own app on top of it with the Dart client in `packages/agent_client` or any
HTTP client.

- [Build the core for a desktop or a server](#build-the-core-for-a-desktop-or-a-server)
- [Run it](#run-it)
- [Build the core for a phone](#build-the-core-for-a-phone)
- [Build an app on the core](#build-an-app-on-the-core)
- [The old reference app](#the-old-reference-app)

The commands to vet and test the core on every system it supports are in
[CONTRIBUTING.md](CONTRIBUTING.md).

## What you need

- **Go**, the release named in `identity-agent-core/go.mod`.
- **macOS only:** the Xcode command line tools (`swiftc`, `lipo`), for the Secure
  Enclave shim below.
- **Phones only:** `gomobile` (below), plus Xcode for iOS or the Android SDK and
  NDK for Android.
- **An app on the core:** Flutter, if you use `packages/agent_client`.

## Build the core for a desktop or a server

Every build runs in `identity-agent-core/` and produces one binary. Pick the
section for the system the binary will run on.

### macOS

The macOS core keeps its signing key in the Secure Enclave. Only CryptoKit can
do that, and cgo cannot compile Swift, so a small Swift shim is built into a
static library first and the core links it. Without the shim, cgo and the
`sepblob` tag, the core still builds but cannot keep a key.

```bash
# From the repository root
bash scripts/build-sep-shim.sh "$PWD/identity-agent-core/build/sep"   # arm64 + x86_64 by default
SEP=$PWD/identity-agent-core/build/sep

cd identity-agent-core
export MACOSX_DEPLOYMENT_TARGET=12.0
for arch in arm64 amd64; do
  CGO_ENABLED=1 CGO_LDFLAGS="$(bash "$SEP/sep-ldflags.sh")" GOOS=darwin GOARCH=$arch \
    go build -tags sepblob -o bin/identity-agent-core-$arch .
done
lipo -create -output bin/identity-agent-core \
  bin/identity-agent-core-arm64 bin/identity-agent-core-amd64

# Asks the binary, not the build, whether the enclave signer made it in
bash "$SEP/sep-assert.sh" bin/identity-agent-core-arm64 bin/identity-agent-core-amd64
```

`MACOSX_DEPLOYMENT_TARGET` stops the linker stamping the binary with the macOS
release of the machine that built it.

### Windows

```powershell
cd identity-agent-core
$env:CGO_ENABLED = "0"; $env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -o bin\identity-agent-core.exe .
```

From macOS or Linux: `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/identity-agent-core.exe .`

### Linux server

```bash
cd identity-agent-core
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/identity-agent-core .   # or GOARCH=arm64
```

A Linux desktop app is not currently supported. To build the sealed server image
an Identity Agent runs in on hardware somebody else owns, and to check its
measurement yourself, see [tools/sealed-image/README.md](tools/sealed-image/README.md).

### Development builds

Every build above is a production build unless you say otherwise. Add the
development mode to any of them with:

```bash
go build -ldflags "-X identity-agent-core/buildmode.rawMode=dev" ...
```

A development build trusts the development keys, reports itself as one on
`/api/health`, and relaxes the gates that refuse a machine that cannot attest. It
must never be given to a user. See
[ADR-043](docs/adr/043-developer-mode-roots-in-a-separate-trust-anchor.md).

### The tunnel helper

Before it has an identity, an Identity Agent can be reached only through a
Cloudflare quick tunnel, which needs `cloudflared`. The core looks for it on the
`PATH`, beside its own executable, and in a `bin/` directory beside that. To
bundle a pinned, checksum-verified copy for macOS or Linux:

```bash
bash scripts/fetch-cloudflared.sh darwin universal <app>/bin/cloudflared   # or: linux amd64
```

The pinned release is in `scripts/cloudflared.version` and its checksums in
`scripts/cloudflared.sha256`; a Windows build downloads
`cloudflared-windows-amd64.exe` of the same release.

## Run it

```bash
cd identity-agent-core
go run .                 # or run a binary built above
curl http://127.0.0.1:5050/api/health
```

The core reads its configuration from the environment:

| Variable | Default | What it sets |
|---|---|---|
| `PORT` | `5050` | The port it listens on. If it is taken, the core takes the next free one. |
| `AGENT_DATA_DIR` | `./data` | Where the identity, its keys and its records are kept. |
| `FLUTTER_WEB_DIR` | unset | A built web app to serve at `/`. Unset, `/` is a placeholder page and only the API is served. |

## Build the core for a phone

On a phone the core runs inside the app's process. `gomobile` turns the
`mobilecore` package into a library the app links.

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
gomobile init

cd identity-agent-core

# iOS: an XCFramework for devices and the Apple-silicon simulator
gomobile bind -target=ios/arm64,iossimulator/arm64 -o Mobilecore.xcframework ./mobilecore

# Android: an AAR (set ANDROID_HOME and ANDROID_NDK_HOME first)
gomobile bind -target=android/arm64 -androidapi 23 -o mobilecore.aar ./mobilecore
```

Add more Android targets (`android/arm`, `android/amd64`) to `-target` for older
devices or the emulator. The app starts the core with `StartServer(dataDir, port)`
and stops it with `StopServer()`; the other exported functions are in
`identity-agent-core/mobilecore/`.

## Build an app on the core

An app talks to the core over HTTP. The routes are registered in
`identity-agent-core/server/server.go` (`buildRouterOf`), all under `/api`.

For a Flutter app, `packages/agent_client` is the client for that API: the
services, configuration, models and signing an app needs, with no screens.
Depend on it from your app's `pubspec.yaml`, either by path from a checkout or
from git at a pinned commit:

```yaml
dependencies:
  agent_client:
    git:
      url: https://github.com/LF-Decentralized-Trust-labs/identity-bot
      path: packages/agent_client
      ref: <commit>
```

The places to start:

- `config/agent_config.dart` — where the core is. On desktop it is
  `http://127.0.0.1:5050`; build with `--dart-define=CORE_URL=...` to point
  elsewhere.
- `services/core_service.dart` — `CoreService`, the client for the core's API.
- `services/backend_process_service.dart` — starts and watches the core on a
  desktop. It looks for the binary in `backend/` beside the app's executable, or
  in `Contents/Resources/backend/` inside a macOS `.app`.
- `services/mobile_core_service.dart` — starts the core on a phone through the
  platform channel `com.identityagent/mobilecore`. Your app's native side
  implements `startServer`, `stopServer`, `isRunning`, `getHealth`, `getPort` and
  `getDataDir` by calling the `Mobilecore` library built above.

Run its tests with `flutter test` in `packages/agent_client`.

## The old reference app

This repository used to contain a Flutter app, `identity_agent_ui`. It was
removed on 2026-10-30 because it had fallen behind the core. The parent of the
commit that removed it is the last that contains it, for anyone who wants to
read it:

```bash
git switch --detach "$(git rev-list -n 1 HEAD -- identity_agent_ui)^"
```

It is outdated: do not expect it to build or to work against today's core.
