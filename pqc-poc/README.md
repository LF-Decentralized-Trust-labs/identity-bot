# Hybrid PQC C4 — liboqs-go toolchain POC (local)

Gating feasibility test for `liboqs-go` × CGO × `gomobile`.

## macOS desktop

```bash
brew install liboqs pkg-config openssl@3
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-go /tmp/liboqs-go
# Edit /tmp/liboqs-go/.config/liboqs-go.pc → Homebrew include/lib paths

export PKG_CONFIG_PATH=/tmp/liboqs-go/.config
export CGO_LDFLAGS="-L/opt/homebrew/lib -loqs -lcrypto"
export DYLD_LIBRARY_PATH=/opt/homebrew/lib

go run ./cmd/c4roundtrip
```

## gomobile (records link failure without mobile liboqs)

```bash
gomobile bind -target=ios -o /tmp/Mobilepqc.xcframework ./mobilepqc
gomobile bind -target=android/arm64 -androidapi 21 -o /tmp/mobilepqc.aar ./mobilepqc
```

