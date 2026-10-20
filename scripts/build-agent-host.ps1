# build-agent-host.ps1 — build agent-host, the program that makes a machine an AI
# agent's body, on Windows. The machine key is a TPM key through the platform
# signer the Identity Agent already uses; no extra toolchain is needed.
#
#   pwsh scripts/build-agent-host.ps1     # -> identity-agent-core\bin\agent-host.exe
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..\identity-agent-core")
New-Item -ItemType Directory -Force -Path bin | Out-Null
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
go build -o bin\agent-host.exe .\cmd\agent-host
if ($LASTEXITCODE -ne 0) { throw "agent-host build failed" }
Write-Host "built identity-agent-core\bin\agent-host.exe"
