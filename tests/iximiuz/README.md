# Manual LDAP JIT test with Iximiuz Labs

This optional test starts an isolated Samba AD domain in a Docker playground. Each tester uses their **own** Iximiuz account; the script never reads or publishes account tokens or account names. Playground IDs and random test passwords exist only in the local process and terminal output, never in the repository. The playground is private, and LDAPS is bound only to its loopback interface.

## Requirements

- A free Iximiuz Labs account and the `labctl` CLI.
- `labctl auth login` completed on your machine. This creates the local SSH key used by `labctl`.
- Windows PowerShell and the OpenSSH client.
- The SubSignature app running locally at `http://127.0.0.1:8100`.

## Start the directory

From the repository root, run:

```powershell
pwsh -NoProfile -File .\tests\iximiuz\start-samba.ps1
```

The script starts a free-tier Docker playground, builds a pinned Samba AD image, provisions the `teste.local` domain, creates one service-bind account plus active and disabled test users, and saves the temporary CA certificate under `%TEMP%`. It prints the one-time passwords and the playground ID only to your local terminal.

The script intentionally leaves a successfully initialized playground running so you can test the login flow. It destroys the playground automatically if setup fails.

## Connect and test

Run the printed `labctl ssh-proxy` command in one terminal and the printed `ssh -N -L` command in another. This forwards the playground's loopback-only LDAPS port to your local machine; it does not expose LDAP to the internet.

The generated server certificate identifies the test DC as `dc1.teste.local`. In an elevated PowerShell terminal, add a temporary hosts-file entry so that name resolves to the local SSH tunnel:

```powershell
Add-Content "$env:WINDIR\System32\drivers\etc\hosts" "127.0.0.1 dc1.teste.local"
```

Remove that line after the test. Configure **Admin → LDAP Import** with the printed CA path and bind credentials, Base DN `DC=teste,DC=local`, the Active Directory preset, verified LDAPS, and JIT enabled.

Then:

1. Use **Test connection** to confirm the service bind and directory search.
2. Sign in with `jit-active` and its printed password. The first successful login should provision an active LDAP user and signature.
3. Sign in with `jit-disabled` and its printed password. The active-account filter should reject it without provisioning a user.

## Cleanup

Stop both SSH tunnel processes with Ctrl+C, destroy the playground using the command printed by the script, and remove the temporary CA directory. The free tier is time-limited and playground storage is ephemeral; this is a manual test environment, not a shared or always-on service.
