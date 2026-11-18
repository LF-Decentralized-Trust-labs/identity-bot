#!/usr/bin/env bash
# Compiles darwin/Classes (Swift) for macOS, an iOS device and the iOS simulator, against the
# Flutter frameworks of the Flutter on PATH. Needs Xcode's command-line tools and Flutter's iOS
# and macOS engine artifacts (`flutter precache --ios --macos`). It proves the Swift compiles;
# it does not run it, and App Attest does not run in a simulator.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
engine="$(dirname "$(command -v flutter)")/cache/artifacts/engine"
src="$here/../Classes/LoginFlutterPlugin.swift"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
build() { # sdk target framework-dir
  xcrun --sdk "$1" swiftc -c -parse-as-library -module-name login_flutter -target "$2" -F "$3" "$src" -o "$out/$1.o"
  echo "Swift compiled for $2"
}
build macosx arm64-apple-macos11.0 "$engine/darwin-x64/FlutterMacOS.xcframework/macos-arm64_x86_64"
build iphoneos arm64-apple-ios14.0 "$engine/ios/Flutter.xcframework/ios-arm64"
build iphonesimulator arm64-apple-ios14.0-simulator "$engine/ios/Flutter.xcframework/ios-arm64_x86_64-simulator"
