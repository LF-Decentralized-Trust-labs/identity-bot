#!/usr/bin/env bash
#
# Package the built Identity Agent macOS .app into a DMG.
# Mirrors the "Create DMG archive" step in codemagic.yaml's `macos-release`.
# Runs whether or not the .app was signed/notarized.
#
# Output: identity-agent-macos.dmg in the repo root.
set -euo pipefail

APP="identity_agent_ui/build/macos/Build/Products/Release/Identity Agent.app"
hdiutil create -volname "Identity Agent" \
  -srcfolder "$APP" \
  -ov -format UDZO \
  "identity-agent-macos.dmg"
ls -lh identity-agent-macos.dmg
