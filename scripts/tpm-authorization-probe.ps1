# Windows probe for ADR-074 section 3: does a TPM key with an authorization value
# behave the way the controller key design needs?
#
# RUN IT (Windows PowerShell, a machine with a TPM 2.0, Go installed, from the
# identity-bot checkout; no administrator rights needed):
#
#     powershell -ExecutionPolicy Bypass -File scripts\tpm-authorization-probe.ps1
#
# It prints one line per claim, PASS / FAIL / UNKNOWN, and ends with
# "PROBE RESULT: ALL PASS" or "PROBE RESULT: NOT READY". Send the whole output
# back. If it says FAIL, do not ship the Windows controller key: the design needs
# a decision (see the line that failed).
#
# WHAT IT DOES
#   0. removes any key an earlier run left (SWEEP)
#   1. builds the probe (identity-agent-core/secureenclave, tag tpmprobe)
#   2. in your session: creates a key with an authorization value, signs with it
#   3. as a scheduled task with NO desktop (this is what the core is): signs again
#   4. in your session: sends ONE wrong value and ONE missing value, reads the
#      TPM's lockout counter before and after
#   5. deletes a key that has an authorization value the way the core deletes one
#      (DELETE), then runs the core's own signer end to end (make, reopen, delete the
#      profile's key, refuse a planted key, refuse when locked)
#   6. deletes every key it made and checks none is left (CLEAN)
#
# If a run leaves a key behind (a crash), run the script again: its first step removes
# them. The probe's keys are named IdentityAgentAuthProbe.v2.*; its one core key is the
# core's name for the profile "identity-agent-tpm-probe-core". It never deletes a key by
# the core's name pattern, since a real profile's key has that name too. A key it cannot
# remove is a FAIL that names it, with the command to delete it by hand:
#     certutil -user -csp "Microsoft Platform Crypto Provider" -delkey <name>
# (Keys left by earlier versions of this probe, named IdentityAgentAuthProbe.<random>
# with a value that was never written down, are never tried: a wrong value counts
# against the lockout counter below. SWEEP names each as information with the
# command above to delete it. The first version's core key, which had a random profile
# id, cannot be told from a real profile's: it is one stale test key and is left alone.)
#
# COST: step 4 adds one or two failures to the TPM's lockout counter, which
# Windows Hello shares, and it decays by itself; DELETE's delete with no value may add
# one more, if the provider passes an empty value to the TPM. The probe refuses to run
# either if fewer than 3 failures remain, so the most it can spend is three.
$ErrorActionPreference = 'Stop'
$me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$repo = Split-Path -Parent $PSScriptRoot
$pkg = Join-Path $repo 'identity-agent-core'
$work = Join-Path $env:TEMP ("tpm-probe-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work | Out-Null
$exe = Join-Path $work 'probe.test.exe'
$state = Join-Path $work 'state.json'
$out = Join-Path $work 'task-output.txt'

Push-Location $pkg
try { go test -c -tags tpmprobe -o $exe ./secureenclave; if ($LASTEXITCODE -ne 0) { throw 'the probe did not build' } } finally { Pop-Location }

function Run-Phase($phase) {
    $env:PROBE_PHASE = $phase; $env:PROBE_STATE = $state
    # stderr must not become a terminating error: a panic is output to read, and the
    # cleanup at the end has to run.
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $lines = & $exe -test.run TestTPMAuthorizationProbe -test.v 2>&1 | ForEach-Object { "$_" }
    $ErrorActionPreference = $prev
    $lines | Out-Host
    return $lines
}

$all = @()
$all += Run-Phase 'sweep'
$all += Run-Phase 'create'
$all += Run-Phase 'sign'

# The same signing, from a process with no desktop and no prompt available.
$cmd = "`$env:PROBE_PHASE='sign'; `$env:PROBE_STATE='$state'; & '$exe' -test.run TestTPMAuthorizationProbe -test.v *> '$out'"
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -Command `"$cmd`""
$principal = New-ScheduledTaskPrincipal -UserId $me -LogonType S4U -RunLevel Limited
$task = 'IdentityAgentTpmProbe'
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $task
$deadline = (Get-Date).AddSeconds(90)
do { Start-Sleep -Seconds 2 } while ((Get-ScheduledTask -TaskName $task).State -eq 'Running' -and (Get-Date) -lt $deadline)
Unregister-ScheduledTask -TaskName $task -Confirm:$false
if (Test-Path $out) { $nonInteractive = Get-Content $out } else { $nonInteractive = @('PROBE SIGN     FAIL  the non-interactive run produced no output') }
$nonInteractive | Out-Host
$all += ($nonInteractive | ForEach-Object { $_ -replace '^PROBE SIGN ', 'PROBE SIGN-NOINTERACTIVE ' })

$all += Run-Phase 'refuse'
$all += Run-Phase 'delete'
$all += Run-Phase 'core'
$all += Run-Phase 'cleanup'
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue

Write-Host ''
Write-Host '---- summary ----'
$lines = $all | Where-Object { $_ -match '^PROBE ' -and $_ -notmatch '^PROBE info' }
$lines | ForEach-Object { Write-Host $_ }
$need = @('SWEEP', 'CREATE', 'SIGN', 'WRONG', 'NONE', 'LOCKOUT', 'SIGN2', 'DELETE', 'CORE', 'CORE-DELETE', 'CORE-OWN', 'CORE-LOCK', 'CLEAN')
$bad = $need | Where-Object { $n = $_; -not ($lines | Where-Object { $_ -match "^PROBE $n\s+PASS" }) }
$noint = $lines | Where-Object { $_ -match '^PROBE SIGN-NOINTERACTIVE\s+PASS' }
if (-not $noint) { $bad += 'SIGN-NOINTERACTIVE' }
if ($bad) { Write-Host "PROBE RESULT: NOT READY ($($bad -join ', '))"; exit 1 }
Write-Host 'PROBE RESULT: ALL PASS'
