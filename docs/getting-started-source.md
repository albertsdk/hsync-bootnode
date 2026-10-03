# Getting Started — Method 4: From source

Run the node directly from a clone as a Python service — for development, or a
host where you control the toolchain. This is the most involved method; for a
managed host prefer the [installer script](getting-started-script.md) or the
[Debian package](getting-started-deb.md).

## Prerequisites

- Python 3.12 or newer
- Poetry
- The `hsync-common` repository checked out as a sibling of `hsync-bootnode`
  (a path dependency of the Python v1)

## Install and run

### Quick path (`run.sh`)

With both repositories cloned side by side:

```bash
git clone <hsync-bootnode-url> hsync-bootnode
git clone <hsync-common-url> hsync-common
cd hsync-bootnode
./run.sh run --host 0.0.0.0 --port 443
```

`run.sh` creates the in-project virtualenv on first use, installs the main
dependencies, and starts the node, forwarding any argument to `hsync-bootnode`
(`./run.sh --help`). It stops with a clear message if `../hsync-common` is
missing.

### Native commands

The same steps, spelled out:

```bash
cd python
poetry config virtualenvs.in-project true
poetry install --only main
.venv/bin/hsync-bootnode run --host 0.0.0.0 --port 443
```

On first run the node creates a persistent identity at
`$XDG_STATE_HOME/hsync/bootnode/identity.pem` (override with `--identity PATH`),
so its fingerprint is stable across restarts and clients can pin it. Read it
with `hsync-bootnode identity show`, and use `--ephemeral` for a throwaway node
that keeps the identity in memory.

Verify it started (another terminal):

```bash
cd python
.venv/bin/hsync-bootnode identity show
```

## Standalone binary (no Python on the target)

`compile.sh` freezes the node into a self-contained executable:

```bash
./compile.sh
# output: dist/<os>-<arch>/hsync-bootnode
./dist/linux-amd64/hsync-bootnode --version
```

Raspberry Pi OS executables (`armhf`/`arm64`) are cross-built inside Docker:

```bash
./compile.sh -t rpi
# output: dist/rpi/armhf/hsync-bootnode and dist/rpi/arm64/hsync-bootnode
```

`native` embeds the host Python and its C library, so a binary copied to a
machine with an older glibc refuses to start; on another machine use the
[Debian package](getting-started-deb.md) instead.

## Use a service manager for an always-on node

For a managed host, run the node with systemd (or launchd/Windows) instead of an
interactive terminal:

```bash
sudo install -m 0640 /path/to/group-keys /etc/hsync-bootnode/group-keys
sudo cp packaging/systemd/hsync-bootnode.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hsync-bootnode.service
```

Edit the executable path inside the unit to your venv or binary. macOS
(`packaging/launchd/`) and Windows (`packaging/windows/`) units are provided
too; see [usage.md → Deploying as a service](usage.md#deploying-as-a-service).

## Update

```bash
cd /path/to/hsync-bootnode
git pull
./run.sh run --host 0.0.0.0 --port 443
```

The persistent identity under the state directory is preserved, so the
fingerprint clients pinned does not change.

## Next

- Prefer a packaged install? [Debian package](getting-started-deb.md).
- Prefer containers? [Installer script](getting-started-script.md) or
  [Docker](getting-started-docker.md).
