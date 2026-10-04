# Getting Started — Windows installer

The installer is **per-machine** (administrator rights). It installs the daemon
and registers it as the Windows service **`hsync-bootnode`** through
[WinSW](https://github.com/winsw/winsw), starting it automatically at boot.

## Prerequisites

- Windows 10/11 or Windows Server (x64)
- Administrator rights
- A UDP port reachable from the Internet (443 by default)

## Install

1. Download `hsync-bootnode-VERSION-windows-amd64-setup.exe` from the release
   page (replace `VERSION` with the release you want).
2. Run it (the wizard prompts for elevation). The service is installed and
   started automatically.

## Manage the service

Run PowerShell **as administrator**:

```powershell
Get-Service hsync-bootnode
Start-Service hsync-bootnode
Stop-Service hsync-bootnode
Restart-Service hsync-bootnode
```

- The TLS identity is persisted under `C:\ProgramData\hsync-bootnode`.
- The service definition is `hsync-bootnode-service.xml` next to
  `hsync-bootnode-service.exe` in the install directory; service logs are written
  alongside it.
- Protected buckets / private node: set `HSYNC_BOOTNODE_PRIVATE` and the group
  keys in the service definition — see [Usage](../docs/usage.md).

## Update and remove

Run the newer installer to upgrade. Removing HSYNC Bootnode from
**Settings → Apps** stops and unregisters the service (the data under
`C:\ProgramData\hsync-bootnode` is left in place).

## Next

- Full operation guide and group keys: see the repository `docs/usage.md`.
