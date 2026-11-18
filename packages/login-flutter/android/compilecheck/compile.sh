#!/usr/bin/env bash
# Compiles android/src (Kotlin) with the plugin's own Gradle build. Needs Gradle 8, a JDK 17, an
# Android SDK with platform 34 (ANDROID_HOME), and Flutter on PATH (its engine version names the
# embedding to compile against).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
flutter_bin="$(dirname "$(command -v flutter)")"
export FLUTTER_ENGINE_VERSION="$(tr -d '[:space:]' < "$flutter_bin/internal/engine.version")"
cd "$here"
printf 'sdk.dir=%s\n' "${ANDROID_HOME:?set ANDROID_HOME}" > local.properties
trap 'rm -f local.properties' EXIT
gradle --no-daemon -q :login_flutter:compileDebugKotlin
echo "android Kotlin compiled"
