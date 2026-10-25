# Getting Started — Method 6: From source

Run the node directly from a clone as a Python service — for development, or a
host where you control the toolchain. This is the most involved method; for a
managed host prefer the [installer script](getting-started-script.md) or the
[Debian package](getting-started-deb.md).

## Prerequisites

- Python 3.12–3.14
- Poetry
- The `hsync-common` repository checked out as a sibling of `hsync-bootnode`
  (a path dependency of the Python v1)

## Install and run

### Quick path (`run.sh`)

With both repositories cloned side by side:

```bash
git clone https://github.com/albertsdk/hsync-bootnode.git hsync-bootnode
git clone https://github.com/albertsdk/hsync-common.git hsync-common
cd hsync-bootnode
./run.sh run
```

`run.sh` creates the in-project virtualenv on first use, installs the main
dependencies, and starts the node, forwarding any argument to `hsync-bootnode`
(`./run.sh --help`). It stops with a clear message if `../hsync-common` is
missing.

### Native commands

The same steps, spelled out (the virtualenv is created by `run.sh`):

```bash
cd python
.venv/bin/hsync-bootnode run
```

On first run the node creates a persistent identity at
`$HSYNC_STATE_DIR/bootnode/identity.pem` (`$XDG_STATE_HOME/hsync/bootnode/identity.pem`
when `HSYNC_STATE_DIR` is unset; override with `--identity PATH`),
so its fingerprint is stable across restarts and clients can pin it. Read it
with `hsync-bootnode identity show` (add the same `--identity PATH` when you
overrode it), and use `--ephemeral` for a throwaway node that keeps the identity
in memory.

Verify it started (another terminal):

```bash
cd python
.venv/bin/hsync-bootnode identity show
```

### Serve a second UDP port (optional)

Clients whose network blocks UDP 443 can still reach the node if it listens
on more than one port. Listen on 443 **and** 53 (a second port must also be
open in the host firewall):

```bash
cd python
.venv/bin/hsync-bootnode run --ports 443,53
```

The ports share one routing table, so a peer registered on one port is
visible to a query on another. See `--ports` in
[usage.md](usage.md#run-options).

## Standalone binary (no Python on the target)

`compile.sh` freezes the node into a self-contained executable:

```bash
./compile.sh
# → dist/<os>-<arch>/hsync-bootnode
./dist/linux-amd64/hsync-bootnode --version
```

Raspberry Pi OS executables (`armhf`/`arm64`) are cross-built inside Docker on
Debian 12 (bookworm); the produced binaries require `libc6 >= 2.35`: use
Raspberry Pi OS **Bookworm** or newer (Bullseye is glibc 2.31 and cannot run
them):

```bash
./compile.sh -t rpi
# → dist/rpi/armhf/hsync-bootnode and dist/rpi/arm64/hsync-bootnode
```

`native` embeds the host Python and its C library, so a binary copied to a
machine with an older glibc refuses to start; on another machine use the
[Debian package](getting-started-deb.md) instead.

## Use a service manager for an always-on node

For a managed host, run the node with systemd (or launchd/Windows) instead of an
interactive terminal:

```bash
sudo install -d -m 0750 /etc/hsync-bootnode
sudo install -m 0640 /path/to/group-keys /etc/hsync-bootnode/group-keys
sudo cp packaging/systemd/hsync-bootnode.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hsync-bootnode.service
```

Edit the executable path inside the unit to your venv or binary. macOS
(`packaging/launchd/`) and Windows (`packaging/windows/`) units are provided
too; the unit reference is
[usage.md → Deploying as a service](usage.md#deploying-as-a-service) and the
operating procedures (watchdog, log bounds, identity backup and rotation,
upgrades, reachability probe) are in [operations.md](operations.md).

## Update

```bash
cd /path/to/hsync-bootnode
git pull
./run.sh run
```

The persistent identity under the state directory is preserved, so the
fingerprint clients pinned does not change.

## Next

- Prefer a packaged install? [Debian package](getting-started-deb.md).
- Prefer containers? [Installer script](getting-started-script.md) or
  [Docker](getting-started-docker.md).
