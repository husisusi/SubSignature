<#
  Set up the SubSignature agent for the logged-in user (no administrator rights needed).

  Usage (in the folder that contains the .exe files):
      powershell -ExecutionPolicy Bypass -File .\install.ps1
      powershell -ExecutionPolicy Bypass -File .\install.ps1 -NoAutostart

  What happens:
    1. The programs are copied to %LOCALAPPDATA%\Programs\SubSignatureAgent.
    2. If %APPDATA%\subsignature-agent\config.xml is missing, a template is created.
    3. Autostart: at logon "subsignature-agentw.exe run" starts (without a window)
       and syncs at the interval from config.xml (default: every 2 hours).

  Deliberately ASCII only (Windows PowerShell does not read files without a BOM as UTF-8).
  Release candidate 1.0.0-rc1: this script has not been run on a real Windows yet.
#>
param([switch]$NoAutostart)

$ErrorActionPreference = 'Stop'
$src    = Split-Path -Parent $MyInvocation.MyCommand.Path
$dest   = Join-Path $env:LOCALAPPDATA 'Programs\SubSignatureAgent'
$cfgDir = Join-Path $env:APPDATA 'subsignature-agent'
$cfg    = Join-Path $cfgDir 'config.xml'
$exe    = Join-Path $dest 'subsignature-agent.exe'
$exeW   = Join-Path $dest 'subsignature-agentw.exe'

foreach ($f in 'subsignature-agent.exe', 'subsignature-agentw.exe') {
    if (-not (Test-Path (Join-Path $src $f))) { throw "File missing next to install.ps1: $f" }
}

# A running agent locks its own .exe - stop it first.
Get-Process -Name 'subsignature-agentw' -ErrorAction SilentlyContinue | Stop-Process -Force

New-Item -ItemType Directory -Force -Path $dest, $cfgDir | Out-Null
Copy-Item -Force -Path (Join-Path $src 'subsignature-agent.exe'), (Join-Path $src 'subsignature-agentw.exe') -Destination $dest

if (-not (Test-Path $cfg)) {
    & $exe init
}

if (-not $NoAutostart) {
    $run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    Set-ItemProperty -Path $run -Name 'SubSignatureAgent' -Value ('"{0}" run' -f $exeW)
    Write-Host 'Autostart set up (starts at the next logon).'
}

Write-Host ''
Write-Host "Installed to:   $dest"
Write-Host "Configuration:  $cfg"
Write-Host "Token file:     $(Join-Path $cfgDir 'token')   (only the token, one line)"
Write-Host ''
Write-Host 'Next steps:'
Write-Host "  1. Enter the <url> of the SubSignature server in config.xml."
Write-Host "  2. Write the token (ssg_...) into the token file."
Write-Host "  3. Check:   `"$exe`" ping"
Write-Host "  4. Preview: `"$exe`" check"
Write-Host "  5. Sync:    `"$exe`" sync    (or log off and on again: then autostart runs)"
