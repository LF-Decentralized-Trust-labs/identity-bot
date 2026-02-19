#!/bin/sh
set -e

WORKSPACE="/home/runner/workspace"

echo "============================================"
echo " IDENTITY AGENT - Flutter Web Build"
echo "============================================"

echo ""
echo "Building Flutter Web..."
cd "$WORKSPACE/identity_agent_ui"
flutter clean
flutter pub get
flutter build web --release --base-href="/"
echo ""
echo "Flutter Web built successfully."
echo "Output: $WORKSPACE/identity_agent_ui/build/web/"
echo ""
echo "The Go backend serves these static files automatically."
echo "Restart the Go backend to pick up the new build."
echo "============================================"
