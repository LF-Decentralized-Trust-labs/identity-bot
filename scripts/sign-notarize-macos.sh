#!/usr/bin/env bash
#
# Sign + notarize the built Identity Agent macOS .app.
#
# Equivalent to the signing/notarization steps in codemagic.yaml's
# `macos-release`, but uses plain `security` + `xcrun notarytool` (the
# codemagic-cli-tools `keychain` command is not present on GitHub runners).
#
# Required env (GitHub Actions secrets — see .github/CI_MACOS_SIGNING_SETUP.md):
#   CM_CERTIFICATE                     base64 of the Developer ID Application .p12
#   CM_CERTIFICATE_PASSWORD            password for that .p12
#   APP_STORE_CONNECT_PRIVATE_KEY      contents of the ASC API key .p8 (for notarytool)
#   APP_STORE_CONNECT_KEY_IDENTIFIER   ASC API key ID
#   APP_STORE_CONNECT_ISSUER_ID        ASC issuer ID
set -euo pipefail

: "${RUNNER_TEMP:=/tmp}"
APP="identity_agent_ui/build/macos/Build/Products/Release/Identity Agent.app"

echo "--- Set up ephemeral signing keychain ---"
KEYCHAIN="$RUNNER_TEMP/identity-agent-signing.keychain-db"
KEYCHAIN_PASSWORD="$(openssl rand -base64 24)"

echo "$CM_CERTIFICATE" | base64 --decode > "$RUNNER_TEMP/developer_id.p12"
curl -sL https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer -o "$RUNNER_TEMP/DeveloperIDG2CA.cer"
curl -sL https://www.apple.com/certificateauthority/AppleWWDRCAG2.cer -o "$RUNNER_TEMP/AppleWWDRCAG2.cer"

security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
# Prepend our keychain to the user search list so codesign can find the identity.
security list-keychains -d user -s "$KEYCHAIN" $(security list-keychains -d user | sed s/\"//g)

security import "$RUNNER_TEMP/DeveloperIDG2CA.cer" -k "$KEYCHAIN" -T /usr/bin/codesign
security import "$RUNNER_TEMP/AppleWWDRCAG2.cer" -k "$KEYCHAIN" -T /usr/bin/codesign
security import "$RUNNER_TEMP/developer_id.p12" -k "$KEYCHAIN" \
  -P "$CM_CERTIFICATE_PASSWORD" \
  -T /usr/bin/codesign -T /usr/bin/security
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN"

echo "--- Verifying certificate in keychain ---"
security find-identity -v -p codesigning "$KEYCHAIN"
rm -f "$RUNNER_TEMP/developer_id.p12" "$RUNNER_TEMP/DeveloperIDG2CA.cer" "$RUNNER_TEMP/AppleWWDRCAG2.cer"

echo "--- Sign the macOS app bundle ---"
IDENTITY=$(security find-identity -v -p codesigning "$KEYCHAIN" | grep "Developer ID Application" | head -1 | awk -F'"' '{print $2}')
if [ -z "$IDENTITY" ]; then
  echo "ERROR: No Developer ID Application certificate found in keychain"
  security find-identity -v -p codesigning "$KEYCHAIN"
  exit 1
fi
echo "Signing with: $IDENTITY"
# Sign nested executables / libraries / frameworks first, then the bundle, with hardened runtime.
find "$APP/Contents/Resources/backend" -type f -perm +111 -exec \
  codesign --force --keychain "$KEYCHAIN" --sign "$IDENTITY" --timestamp --options runtime {} \;
find "$APP" -type f -name "*.dylib" -exec \
  codesign --force --keychain "$KEYCHAIN" --sign "$IDENTITY" --timestamp --options runtime {} \; 2>/dev/null || true
find "$APP" -type d -name "*.framework" -exec \
  codesign --force --keychain "$KEYCHAIN" --sign "$IDENTITY" --timestamp --options runtime {} \; 2>/dev/null || true
codesign --force --deep --keychain "$KEYCHAIN" --sign "$IDENTITY" --timestamp --options runtime "$APP"
codesign --verify --deep --strict "$APP" && echo "Signature valid"

echo "--- Notarize the macOS app ---"
ditto -c -k --keepParent "$APP" "$RUNNER_TEMP/Identity_Agent.zip"
echo "$APP_STORE_CONNECT_PRIVATE_KEY" > "$RUNNER_TEMP/api_key.p8"
set +e
xcrun notarytool submit "$RUNNER_TEMP/Identity_Agent.zip" \
  --key "$RUNNER_TEMP/api_key.p8" \
  --key-id "$APP_STORE_CONNECT_KEY_IDENTIFIER" \
  --issuer "$APP_STORE_CONNECT_ISSUER_ID" \
  --wait 2>&1 | tee "$RUNNER_TEMP/notarytool_output.txt"
set -e
SUBMISSION_ID=$(grep "id:" "$RUNNER_TEMP/notarytool_output.txt" | head -1 | awk '{print $2}')
if grep -q "Invalid" "$RUNNER_TEMP/notarytool_output.txt"; then
  echo "--- Notarization FAILED — fetching detailed log ---"
  xcrun notarytool log "$SUBMISSION_ID" \
    --key "$RUNNER_TEMP/api_key.p8" \
    --key-id "$APP_STORE_CONNECT_KEY_IDENTIFIER" \
    --issuer "$APP_STORE_CONNECT_ISSUER_ID" \
    "$RUNNER_TEMP/notary_log.json"
  cat "$RUNNER_TEMP/notary_log.json"
  rm -f "$RUNNER_TEMP/api_key.p8" "$RUNNER_TEMP/Identity_Agent.zip"
  exit 1
fi
rm -f "$RUNNER_TEMP/api_key.p8"

echo "--- Stapling notarization ticket ---"
xcrun stapler staple "$APP"
spctl --assess --type execute "$APP" && echo "App is notarized and accepted by Gatekeeper"
rm -f "$RUNNER_TEMP/Identity_Agent.zip"
