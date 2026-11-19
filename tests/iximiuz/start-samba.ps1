[CmdletBinding()]
param(
    [string]$Title = 'SubSignature LDAP JIT test'
)

$ErrorActionPreference = 'Stop'
$playgroundId = $null

function Invoke-Labctl {
    param([Parameter(Mandatory)][string[]]$Arguments)

    & labctl @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "labctl command failed: $($Arguments -join ' ')"
    }
}

function New-TestPassword {
    $bytes = [byte[]]::new(24)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return 'Aa1-' + [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', 'A').Replace('/', 'B')
}

try {
    if (-not (Get-Command labctl -ErrorAction SilentlyContinue)) {
        throw 'Install labctl and run labctl auth login before starting this test.'
    }

    $sshIdentity = Join-Path $HOME '.ssh\iximiuz_labs_user'
    if (-not (Test-Path $sshIdentity) -or -not (Test-Path "$sshIdentity.pub")) {
        throw 'The Iximiuz SSH key is missing. Run labctl auth login, then retry.'
    }

    $playgroundOutput = & labctl playground start docker --as-free-tier-user --title $Title --quiet
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not start the free-tier Docker playground.'
    }
    $playgroundId = (@($playgroundOutput) -join '').Trim()
    if ([string]::IsNullOrWhiteSpace($playgroundId)) {
        throw 'labctl started no playground or returned an empty ID.'
    }

    $sourceCommit = '68b22b7f771d9c3aa9cc94b7565b277a075c7d53'
    Invoke-Labctl @('ssh', $playgroundId, '--', 'mkdir', '-p', '/tmp/samba-domain')
    Invoke-Labctl @('ssh', $playgroundId, '--', 'curl', '-fsSL', "https://github.com/Fmstrat/samba-domain/archive/$sourceCommit.tar.gz", '-o', '/tmp/samba-domain.tar.gz')
    Invoke-Labctl @('ssh', $playgroundId, '--', 'tar', '-xzf', '/tmp/samba-domain.tar.gz', '--strip-components=1', '-C', '/tmp/samba-domain')
    Invoke-Labctl @('ssh', $playgroundId, '--', 'docker', 'build', '-t', 'local/samba-domain:source', '/tmp/samba-domain')

    $domainPassword = New-TestPassword
    $servicePassword = New-TestPassword
    $activePassword = New-TestPassword
    $disabledPassword = New-TestPassword

    Invoke-Labctl @(
        'ssh', $playgroundId, '--', 'docker', 'run', '-d',
        '--name', 'samba-ad',
        '--hostname', 'dc1',
        '-e', 'DOMAIN=TESTE.LOCAL',
        '-e', "DOMAINPASS=$domainPassword",
        '-p', '127.0.0.1:1636:636',
        '--privileged',
        'local/samba-domain:source'
    )

    $domainReady = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $null = & labctl ssh $playgroundId -- docker exec samba-ad samba-tool domain info 127.0.0.1 2>$null
        if ($LASTEXITCODE -eq 0) {
            $domainReady = $true
            break
        }
        Start-Sleep -Seconds 2
    }
    if (-not $domainReady) {
        throw 'Samba AD did not finish provisioning within 2 minutes.'
    }

    Invoke-Labctl @('ssh', $playgroundId, '--', 'docker', 'exec', 'samba-ad', 'samba-tool', 'user', 'create', 'svc-subsig', $servicePassword)
    Invoke-Labctl @('ssh', $playgroundId, '--', 'docker', 'exec', 'samba-ad', 'samba-tool', 'user', 'create', 'jit-active', $activePassword, '--given-name', 'JIT', '--surname', 'Active', '--mail-address', 'jit-active@teste.local')
    Invoke-Labctl @('ssh', $playgroundId, '--', 'docker', 'exec', 'samba-ad', 'samba-tool', 'user', 'create', 'jit-disabled', $disabledPassword, '--given-name', 'JIT', '--surname', 'Disabled', '--mail-address', 'jit-disabled@teste.local')
    Invoke-Labctl @('ssh', $playgroundId, '--', 'docker', 'exec', 'samba-ad', 'samba-tool', 'user', 'disable', 'jit-disabled')

    $caOutput = & labctl ssh $playgroundId -- docker exec samba-ad base64 -w0 /var/lib/samba/private/tls/ca.pem
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not retrieve the Samba test CA certificate.'
    }
    $caBytes = [Convert]::FromBase64String((@($caOutput) -join '').Trim())
    $caDirectory = Join-Path $env:TEMP "SubSignature-Iximiuz-$playgroundId"
    New-Item -ItemType Directory -Path $caDirectory -Force | Out-Null
    $caFile = Join-Path $caDirectory 'samba-ad-ca.pem'
    [System.IO.File]::WriteAllBytes($caFile, $caBytes)

    Write-Host ''
    Write-Host 'The private free-tier playground and Samba AD test users are ready.'
    Write-Host "Playground ID (local only): $playgroundId"
    Write-Host 'LDAPS is bound to the playground loopback only; no LDAP port is public.'
    Write-Host ''
    Write-Host 'In a separate terminal, start the private SSH proxy:'
    Write-Host "  labctl ssh-proxy $playgroundId --address 127.0.0.1:2222"
    Write-Host ''
    Write-Host 'In another terminal, forward LDAPS to your local machine:'
    Write-Host "  ssh -N -L 1636:127.0.0.1:1636 -p 2222 -i `"$sshIdentity`" laborant@127.0.0.1"
    Write-Host ''
    Write-Host 'Configure SubSignature Admin > LDAP Import with:'
    Write-Host '  Host: dc1.teste.local (resolve this name to 127.0.0.1 on your machine)'
    Write-Host '  Port: 1636; Encryption: LDAPS; certificate verification: enabled'
    Write-Host "  CA file: $caFile"
    Write-Host '  Base DN: DC=teste,DC=local'
    Write-Host '  Bind DN: CN=svc-subsig,CN=Users,DC=teste,DC=local'
    Write-Host "  Bind password: $servicePassword"
    Write-Host ''
    Write-Host "Active test login: jit-active / $activePassword"
    Write-Host "Disabled test login: jit-disabled / $disabledPassword"
    Write-Host ''
    Write-Host "After testing, destroy the playground with: labctl playground destroy $playgroundId"
    Write-Host "Remove the temporary CA directory with: Remove-Item -Recurse -Force `"$caDirectory`""
}
catch {
    if ($playgroundId) {
        & labctl playground destroy $playgroundId --quiet 2>$null | Out-Null
    }
    throw
}
