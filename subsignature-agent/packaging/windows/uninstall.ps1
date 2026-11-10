<#
  Remove the SubSignature agent for the logged-in user.

      powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
      powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -KeepSignatures

  Without -KeepSignatures the agent first undoes everything it has set up in Thunderbird
  and Outlook ("subsignature-agent remove").
  Configuration and token under %APPDATA%\subsignature-agent are kept.

  Deliberately ASCII only (Windows PowerShell does not read files without a BOM as UTF-8).
  ALPHA: this script has been written but not yet run on a real Windows.
#>
param([switch]$KeepSignatures)

$ErrorActionPreference = 'Stop'
$dest = Join-Path $env:LOCALAPPDATA 'Programs\SubSignatureAgent'
$exe  = Join-Path $dest 'subsignature-agent.exe'
$run  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

Get-Process -Name 'subsignature-agentw' -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-ItemProperty -Path $run -Name 'SubSignatureAgent' -ErrorAction SilentlyContinue

if (-not $KeepSignatures -and (Test-Path $exe)) {
    Start-Sleep -Seconds 1      # the stopped agent releases its lock
    & $exe remove
}

if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
Write-Host 'SubSignature agent removed. Configuration and token are still in:'
Write-Host "  $(Join-Path $env:APPDATA 'subsignature-agent')"
