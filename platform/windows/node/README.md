# Run GNUnet as a Windows service

The Windows executable supports one own-process Service Control Manager (SCM)
service named `gnunet-node`. It uses the same node options and peer protocol as
the foreground executable. Set the options in the installed `ImagePath`.

## Install and configure

Install the staged `bin/gnunet-node.exe` and data under an administrator-owned
installation prefix. Use a dedicated non-administrator account with **Log on as
a service**. Create distinct, short absolute state and IPC directories on the
local system. Set their owner to the service account and restrict their DACLs to
that account, SYSTEM and Administrators. Keep the parent namespace protected
against replacement by other users. For existing state, preserve the original
account, ownership and key files.

In elevated PowerShell, substitute the service account and provisioned paths.
The example enables outbound TCP peering and local IPC.

```powershell
$account = Get-Credential "$env:COMPUTERNAME\gnunet"
$command = '"C:\Program Files\GNUnet\bin\gnunet-node.exe" --windows-service --state-directory "C:\ProgramData\GNUnet\state" --ipc-directory "C:\ProgramData\GNUnet\run" --outbound-tcp'
New-Service -Name 'gnunet-node' -DisplayName 'GNUnet node' `
    -BinaryPathName $command -Credential $account -StartupType Manual
```

Keep the executable path quoted in `ImagePath`. Use `--config` with an absolute
path readable by the service account for explicit GNUnet configuration. Use
`--bootstrap-data-directory` when the deployment supplies packaged `hellos` and
`--dns-server ADDRESS:PORT` to specify an upstream DNS endpoint. For a listening
node, use `--tcp-bind ADDRESS:PORT` or `--tcp-dual-stack PORT` with
`--udp4-bind ADDRESS:PORT` and optional `--udp6-bind ADDRESS:PORT` in place of
`--outbound-tcp`. Configure Windows Firewall separately for the selected binds.
[Service registration](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/new-service)

The NAT reversal helpers use the service's existing token. Enable the helper
directory option only for a deployment with permission to open Winsock raw
sockets. The dedicated non-administrator example uses ordinary NAT discovery.
[Winsock raw-socket permissions](https://learn.microsoft.com/windows/win32/winsock/tcp-ip-raw-sockets-2)

## Operate

```powershell
Start-Service gnunet-node
Get-Service gnunet-node
Stop-Service gnunet-node
```

SCM shows `StartPending` until the node reports readiness. Stop requests and
system shutdown notifications begin ordered retirement. SCM shows `Stopped`
after the node and its native subscriptions have retired. Windows can enforce
its own limit during system shutdown. Use `--startup-timeout-ms` and
`--drain-timeout-ms` to set the startup and TRANSPORT drain budgets.

For failures, check the System log for the SCM result and the Application log
for `gnunet-node` event details. After stopping the service, unregister it with
`sc.exe delete gnunet-node`. Persistent state remains in the selected directory.
[SCM status values](https://learn.microsoft.com/windows/win32/api/winsvc/ns-winsvc-service_status)
