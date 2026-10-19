<#
  Build + bundle the Identity Agent Windows desktop release.

  The build steps for a Windows release, kept as a script so CI and a developer
  run the same logic. The CALLER is responsible for installing the toolchain
  first:
    - Go 1.24.0
    - Flutter 3.27.3

  Env:
    BUILD_NUMBER  optional build number (defaults to 0)

  Output: identity-agent-windows-x64.zip in the repo root.
#>
$ErrorActionPreference = "Stop"

if (-not $env:BUILD_NUMBER) { $env:BUILD_NUMBER = "0" }

Write-Host "--- Build Go backend (Windows) ---"
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
Push-Location identity-agent-core
go build -o bin\identity-agent-core.exe .
if ($LASTEXITCODE -ne 0) { throw "Go backend build failed" }
Get-Item bin\identity-agent-core.exe
Pop-Location

Write-Host "--- Get Flutter packages ---"
Push-Location identity_agent_ui
flutter pub get
if ($LASTEXITCODE -ne 0) { throw "flutter pub get failed" }
Pop-Location

Write-Host "--- Build Flutter Windows app ---"
Push-Location identity_agent_ui
flutter build windows --release --build-number=$env:BUILD_NUMBER
if ($LASTEXITCODE -ne 0) { throw "flutter build windows failed" }
Pop-Location

# The KERI engine (keri-go) is compiled into identity-agent-core.exe, so bundling
# the Go backend is all that is needed to establish and run an identity. There is
# no Python involved: keri-go runs in-process and is the only KERI engine. (It
# uses pure-Go crypto, so no libsodium.dll is bundled either — that was pysodium's.)
Write-Host "--- Bundle Go backend with Flutter app ---"
$BUNDLE = "identity_agent_ui\build\windows\x64\runner\Release"
New-Item -ItemType Directory -Force -Path "$BUNDLE\backend" | Out-Null
New-Item -ItemType Directory -Force -Path "$BUNDLE\backend\bin" | Out-Null
Copy-Item "identity-agent-core\bin\identity-agent-core.exe" "$BUNDLE\backend\"
Copy-Item -Recurse -Force "manifests" "$BUNDLE\backend\manifests"
Write-Host "Building go-demo sandbox app..."
Push-Location "sandbox-apps\go-demo"
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -buildvcs=false -ldflags="-s -w" -o "..\..\$BUNDLE\backend\bin\go-demo.exe" .
if ($LASTEXITCODE -ne 0) { Write-Error "go-demo build failed!"; exit 1 }
Pop-Location
Write-Host "--- Bundle contents ---"
Get-ChildItem -Recurse "$BUNDLE\backend"

Write-Host "--- Create ZIP archive ---"
Compress-Archive -Path "$BUNDLE\*" -DestinationPath "identity-agent-windows-x64.zip" -Force
Get-Item "identity-agent-windows-x64.zip"
