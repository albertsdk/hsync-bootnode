# Getting Started — Method 3: Debian/Ubuntu package

The `.deb` installs the node as a hardened systemd service under a dynamic user
with `CAP_NET_BIND_SERVICE` (so it can bind UDP 443), and provisions group keys
as a systemd credential. No Docker and no Python are required.

## Prerequisites

- Debian or Ubuntu, `amd64`, `arm64` or `armhf`
- A root shell or `sudo`
- A UDP port reachable from the Internet (443 by default)

## Install

### From the release (recommended)

Download the package for your architecture from the release page and install it:

```bash
curl -fLO "https://github.com/albertsdk/hsync-bootnode/releases/latest/download/hsync-bootnode_VERSION_ARCH.deb"
sudo dpkg -i hsync-bootnode_VERSION_ARCH.deb
sudo apt install -f
```

Replace `VERSION` and `ARCH` with the release you downloaded (for example
`1.0.0` and `amd64`). To install a specific version, use the URL of that release
(replace `latest/download` with `download/vX.Y.Z`).

### Build from the checkout

From the `hsync-bootnode` checkout (needs Docker for the cross build):

```bash
./compile.sh -t deb
# output: dist/deb/hsync-bootnode_<ver>_<arch>.deb
```

`./compile.sh -t deb-all` cross-builds the `amd64`, `arm64` and `armhf` packages
inside Docker.

## Provision group keys (protected buckets / private node)

Group keys are a secret provisioned by the administrator, never shipped in the
package. Install the file and the service unit picks it up as a systemd
credential:

```bash
sudo install -m 0640 /path/to/group-keys /etc/hsync-bootnode/group-keys
```

The file has one `bucket=<hex-group-key>` line per protected bucket. With the
file present, the unit passes `--keys-fd`; to make a bucket protected, add
`--protected-bucket BUCKET` with a drop-in, and for a fully private node set:

```bash
sudo systemctl edit hsync-bootnode.service
```

```ini
[Service]
Environment=HSYNC_BOOTNODE_PRIVATE=1
```

## Start the service

The package never enables the service automatically (opt-in start):

```bash
sudo systemctl enable --now hsync-bootnode.service
sudo systemctl status hsync-bootnode.service
```

## Verify the node is running

```bash
sudo journalctl -u hsync-bootnode.service -f
sudo hsync-bootnode identity show
```

The identity command prints the certificate fingerprint clients pin. The
persistent identity lives at the node's state path and stays stable across
restarts.

## Manage and update

```bash
sudo systemctl status hsync-bootnode.service
sudo journalctl -u hsync-bootnode.service -f
sudo systemctl restart hsync-bootnode.service
```

To update, install the newer `.deb` over the existing one (`sudo dpkg -i …`); the
group keys are preserved. See
[Operations](https://github.com/albertsdk/hsync-server/blob/main/docs/operations.md)
for the ecosystem-wide upgrade guidance.

## Next

- Prefer containers? [Installer script](getting-started-script.md) or
  [Docker](getting-started-docker.md).
- Running directly from a clone? [From source](getting-started-source.md).
