<#
  Remove the SubSignature agent for the logged-in user.

      powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
      powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -KeepSignatures

  Without -KeepSignatures the agent first undoes everything it has set up in Thunderbird
  and Outlook ("subsignature-agent remove").
  Configuration and token under %APPDATA%\subsignature-agent are kept.

  Outlook must be closed for this (the agent does not change Outlook while it runs).
  If "remove" fails, nothing is uninstalled, so it can be run again.

  Deliberately ASCII only (Windows PowerShell does not read files without a BOM as UTF-8).
  Release candidate 1.0.0-rc1: this script has not been run on a real Windows yet.
#>
param([switch]$KeepSignatures)

$ErrorActionPreference = 'Stop'
$dest = Join-Path $env:LOCALAPPDATA 'Programs\SubSignatureAgent'
$exe  = Join-Path $dest 'subsignature-agent.exe'
$run  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

if (-not $KeepSignatures -and (Get-Process -Name 'OUTLOOK' -ErrorAction SilentlyContinue)) {
    Write-Host 'Outlook is running. Please close Outlook and run uninstall.ps1 again.'
    exit 1
}

Get-Process -Name 'subsignature-agentw' -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-ItemProperty -Path $run -Name 'SubSignatureAgent' -ErrorAction SilentlyContinue

if (-not $KeepSignatures -and (Test-Path $exe)) {
    Start-Sleep -Seconds 1      # the stopped agent releases its lock
    & $exe remove
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'remove reported an error (see above). The agent stays installed so that remove can be run again:'
        Write-Host "  & '$exe' remove"
        exit 1
    }
}

if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
Write-Host 'SubSignature agent removed. Configuration and token are still in:'
Write-Host "  $(Join-Path $env:APPDATA 'subsignature-agent')"
