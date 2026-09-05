#!/usr/bin/env bash
# Compile the Swift the macOS core needs to hold a key in the Secure Enclave.
#
# Only CryptoKit exposes the enclave's wrapped key blob, and cgo cannot compile
# Swift — so the Swift becomes a static library first and cgo links it. That is
# the whole reason this file exists.
#
# Why the blob rather than the keychain: an enclave key is never stored in the
# enclave. The enclave wraps it and returns something only that chip can unwrap,
# and the keychain was only ever holding that. Asking the keychain to hold it
# needs an entitlement, authorised by a provisioning profile, embedded in an
# app-like bundle — and the core is a bare executable inside the app's Resources,
# with nowhere to put a profile. Holding the blob ourselves is the same hardware
# and the same guarantee, without any of that.
#
#   build-sep-shim.sh <output-dir> [arch...]
#
# Produces libsep.a in the output directory. Build the core with `-tags sepblob`
# and CGO_LDFLAGS pointing at it, or the core falls back to the keychain signer
# and correctly refuses to hold a key.
set -euo pipefail

OUT=${1:?output directory required}
shift || true
ARCHES=("$@")
[[ ${#ARCHES[@]} -gt 0 ]] || ARCHES=(arm64 x86_64)

[[ "$(uname -s)" == "Darwin" ]] || { echo "the enclave shim is macOS only" >&2; exit 1; }
command -v swiftc >/dev/null || { echo "swiftc not found — install the Xcode command line tools" >&2; exit 1; }

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/identity-agent-core/secureenclave/sep/sep.swift"
[[ -f "$SRC" ]] || { echo "missing $SRC" >&2; exit 1; }

# The oldest macOS this shim serves. Kept low on purpose: raising it to 13 would
# make the compatibility problem below disappear by dropping support for Macs
# that work perfectly well, which is not a trade worth making silently.
FLOOR="${MACOSX_DEPLOYMENT_TARGET:-12.0}"

# WHERE THE BACK-DEPLOYMENT LIBRARIES LIVE, and why the link needs to be told.
#
# Building for a floor older than the running toolchain makes swiftc emit
# references to compatibility shims — swiftCompatibility56 and friends — which
# are static libraries shipped inside Xcode rather than in /usr/lib/swift. Nothing
# adds that directory automatically, so the core fails to link on an undefined
# symbol that names a library the machine does have.
#
# Emitted here rather than hardcoded in the cgo file, because it is a property of
# the toolchain doing the building, not of the source.
SWIFT_COMPAT_DIR="$(xcode-select -p)/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/macosx"
[[ -d "$SWIFT_COMPAT_DIR" ]] || {
  echo "no Swift compatibility libraries at $SWIFT_COMPAT_DIR" >&2; exit 1; }

mkdir -p "$OUT"

# One slice per architecture, then lipo — the core ships universal, and a shim
# built for one architecture makes the other slice fail to link rather than fall
# back, which is the better failure but only if it happens at build time.
SLICES=()
for arch in "${ARCHES[@]}"; do
  # -target names the ARCHITECTURE, which is what makes a universal binary
  # possible: swiftc builds one slice at a time and without it there is only the
  # host's. MACOSX_DEPLOYMENT_TARGET is set alongside it so the clang that cgo
  # invokes agrees with swiftc about how old a Mac this serves.
  #
  # Naming a floor older than the toolchain makes swiftc emit back-deployment
  # compatibility shims, which reference static libraries that live inside Xcode
  # rather than /usr/lib/swift — so the core fails to link on an undefined
  # swiftCompatibility symbol until the link is told where they are. That is what
  # SWIFT_COMPAT_DIR above is for. Raising the floor to 13 would make the shims
  # disappear and take working Macs with it, which is not a trade to make by
  # accident.
  MACOSX_DEPLOYMENT_TARGET="$FLOOR" \
  swiftc -emit-library -static -O \
    -target "${arch}-apple-macos${FLOOR}" \
    -module-name sep \
    -o "$OUT/libsep-${arch}.a" "$SRC"
  SLICES+=("$OUT/libsep-${arch}.a")
done

if [[ ${#SLICES[@]} -gt 1 ]]; then
  lipo -create -output "$OUT/libsep.a" "${SLICES[@]}"
else
  cp "${SLICES[0]}" "$OUT/libsep.a"
fi

echo "  libsep.a: $(lipo -archs "$OUT/libsep.a" 2>/dev/null || echo "${ARCHES[*]}") (macOS $FLOOR and later)"

# The link flags a caller needs, written down rather than left to be rediscovered.
# Source this, or read it — either way the knowledge lives with the artifact.
cat > "$OUT/sep-ldflags.sh" <<FLAGS
# Produced by build-sep-shim.sh. Build the core with:
#   CGO_LDFLAGS="\$(bash $OUT/sep-ldflags.sh)" go build -tags sepblob
echo "-L$OUT -L$SWIFT_COMPAT_DIR"
FLAGS
echo "  link with: -L$OUT -L$SWIFT_COMPAT_DIR"
