# build-agent-host.ps1 — build agent-host, the program that makes a machine an AI
# agent's body, on Windows. On Windows its key is a key file, at the software
# grade: the TPM key has one fixed name per machine and is already the Identity
# Agent's own, so a body does not use it until a per-body TPM key is built.
#
#   pwsh scripts/build-agent-host.ps1 [-Arch amd64|arm64]   # -> identity-agent-core\bin\agent-host.exe
param([ValidateSet("amd64", "arm64")][string]$Arch = "amd64")
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..\identity-agent-core")
New-Item -ItemType Directory -Force -Path bin | Out-Null
$env:GOOS = "windows"; $env:GOARCH = $Arch; $env:CGO_ENABLED = "0"
go build -o bin\agent-host.exe .\cmd\agent-host
if ($LASTEXITCODE -ne 0) { throw "agent-host build failed" }
Write-Host "built identity-agent-core\bin\agent-host.exe"
