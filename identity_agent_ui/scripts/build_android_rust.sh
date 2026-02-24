#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RUST_DIR="$PROJECT_DIR/rust"
ANDROID_DIR="$PROJECT_DIR/android"

LIB_NAME="libidentity_agent_keri.so"

declare -A TARGET_MAP=(
  ["aarch64-linux-android"]="arm64-v8a"
  ["armv7-linux-androideabi"]="armeabi-v7a"
  ["x86_64-linux-android"]="x86_64"
)

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  echo "Error: ANDROID_NDK_HOME is not set."
  echo "Set it to your Android NDK path, e.g.:"
  echo "  export ANDROID_NDK_HOME=\$HOME/Android/Sdk/ndk/<version>"
  exit 1
fi

TOOLCHAIN_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
if [ ! -d "$TOOLCHAIN_BIN" ]; then
  TOOLCHAIN_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin"
fi
if [ ! -d "$TOOLCHAIN_BIN" ]; then
  TOOLCHAIN_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-arm64/bin"
fi

export PATH="$TOOLCHAIN_BIN:$PATH"

echo "=== Installing Rust Android targets ==="
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

echo "=== Building Rust library for Android ==="
cd "$RUST_DIR"

for TARGET in "${!TARGET_MAP[@]}"; do
  ABI="${TARGET_MAP[$TARGET]}"
  echo "--- Building for $TARGET ($ABI) ---"
  cargo build --release --target "$TARGET"

  JNILIB_DIR="$ANDROID_DIR/app/src/main/jniLibs/$ABI"
  mkdir -p "$JNILIB_DIR"
  cp "target/$TARGET/release/$LIB_NAME" "$JNILIB_DIR/$LIB_NAME"
  echo "  -> Copied to $JNILIB_DIR/$LIB_NAME"
done

echo "=== Android Rust build complete ==="
