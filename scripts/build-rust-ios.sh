#!/bin/bash
set -euo pipefail

RUST_DIR="identity_agent_ui/rust"
IOS_DIR="identity_agent_ui/ios"
LIB_NAME="libidentity_agent_keri.a"

echo "============================================"
echo " Rust KERI Bridge — iOS Build"
echo "============================================"

source "$HOME/.cargo/env" 2>/dev/null || true

echo "[1/4] Checking Rust iOS targets..."
rustup target add aarch64-apple-ios
rustup target add aarch64-apple-ios-sim

echo "[2/4] Building for aarch64-apple-ios (device)..."
cd "$RUST_DIR"
cargo build --release --target aarch64-apple-ios
echo "      Device build complete."

echo "[3/4] Building for aarch64-apple-ios-sim (simulator)..."
cargo build --release --target aarch64-apple-ios-sim
echo "      Simulator build complete."

echo "[4/4] Creating universal libraries..."
DEVICE_LIB="target/aarch64-apple-ios/release/$LIB_NAME"
SIM_LIB="target/aarch64-apple-ios-sim/release/$LIB_NAME"

mkdir -p "../../$IOS_DIR/Frameworks/RustKeri/device"
mkdir -p "../../$IOS_DIR/Frameworks/RustKeri/simulator"

cp "$DEVICE_LIB" "../../$IOS_DIR/Frameworks/RustKeri/device/$LIB_NAME"
cp "$SIM_LIB"    "../../$IOS_DIR/Frameworks/RustKeri/simulator/$LIB_NAME"

DEVICE_OUT="../../$IOS_DIR/Frameworks/RustKeri/device/$LIB_NAME"
SIM_OUT="../../$IOS_DIR/Frameworks/RustKeri/simulator/$LIB_NAME"

echo ""
echo "--- Built static libraries ---"
ls -lh "$DEVICE_OUT"
ls -lh "$SIM_OUT"
echo ""
echo "  Device (.a):    $IOS_DIR/Frameworks/RustKeri/device/$LIB_NAME"
echo "  Simulator (.a): $IOS_DIR/Frameworks/RustKeri/simulator/$LIB_NAME"
echo ""
echo "  Xcode will select the correct architecture automatically."
echo "  For XCFramework (optional), run:"
echo "    xcodebuild -create-xcframework \\"
echo "      -library $IOS_DIR/Frameworks/RustKeri/device/$LIB_NAME \\"
echo "      -library $IOS_DIR/Frameworks/RustKeri/simulator/$LIB_NAME \\"
echo "      -output $IOS_DIR/Frameworks/RustKeri.xcframework"
echo "============================================"
