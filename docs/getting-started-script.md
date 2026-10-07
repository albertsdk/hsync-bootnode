# Getting Started — Method 1: Installer script

The `install.sh` installer is the recommended way to get a bootnode running: it
downloads the released container image, persists the TLS identity in a plain
host directory, and starts the node with Docker Compose.

## Prerequisites

- <img src="assets/os/linux.svg" alt="Linux" width="16" height="16"> <img src="assets/os/apple.svg" alt="macOS" width="16" height="16"> Linux or macOS with Docker Engine or Docker Desktop running
- Docker Compose v2 (`docker compose version`)
- `cosign` on `PATH` — the installer verifies the container image's Sigstore
  signature before starting it (pass `--no-verify` to install without it)
- A UDP port reachable from the Internet (443 by default)

Docker must already be installed. The installer never invokes `sudo`, opens
firewall ports, or changes router settings.

## Install

### Quick install (one command, latest stable release)

```bash
curl -fsSL https://github.com/albertsdk/hsync-bootnode/releases/latest/download/install.sh | bash
```

This downloads and runs the installer in one step. The host's UDP port `443` is
mapped to the container; the node's persistent TLS identity lives in
`~/.local/share/hsync-bootnode/hsync-data`.

### Verified install (checksum)

To verify the download before running it:

```bash
curl -fLO "https://github.com/albertsdk/hsync-bootnode/releases/latest/download/install.sh"
curl -fLO "https://github.com/albertsdk/hsync-bootnode/releases/latest/download/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
chmod 700 install.sh
./install.sh
```

On macOS, use `shasum -a 256 install.sh` and compare the result with the
matching line in `SHA256SUMS`.

### Verify the container image

Before starting the node, the installer verifies the released image's
**Sigstore (cosign) signature** — keyless, signed by the release workflow — and
refuses to start an image whose signature does not match. This needs `cosign`
on `PATH`. To pin an exact image instead of a mutable tag:

```bash
./install.sh --image-digest sha256:<64-hex-digest>
```

If you cannot install `cosign`, `--no-verify` skips the check (the image is then
trusted on the registry reference alone):

```bash
./install.sh --no-verify
```

### Choose the host port

Clients connect to the host's UDP port (`443`); the container maps it to an
unprivileged internal port. To use another public port, for example `8443`:

```bash
./install.sh --port 8443
```

### Private node (authenticated bootstrap)

A **private** node requires a valid `bucket_token` on every frame. Provision the
group keys with a `bucket=<hex-group-key>` line per protected bucket:

```bash
./install.sh --private --keys-file /secure/path/group-keys
```

## Verify the node is running

The installer waits for the node to write its readiness PID. Check the logs and
the certificate fingerprint clients pin:

```bash
cd "$HOME/.local/share/hsync-bootnode"
docker compose ps
docker compose logs | grep -i fingerprint
```

## Manage and update

```bash
cd "$HOME/.local/share/hsync-bootnode"
docker compose logs -f
docker compose restart
docker compose down
docker compose up -d
```

`docker compose down` does not delete the identity directory. To update, run the
installer again with the same directory: it updates the pinned image version
while preserving the TLS identity (so the fingerprint clients pinned stays the
same).

```bash
./install.sh
```

Run `./install.sh --help` for version, install-directory, port, `--private`,
`--keys-file`, `--image-digest`, `--no-verify`, `--no-start` and `--dry-run`
options.

## Next

- Prefer to manage containers yourself? [Docker / Compose](getting-started-docker.md).
- No Docker host? [Debian package](getting-started-deb.md) or
  [run from source](getting-started-source.md).
