# Getting Started — RPM package (RHEL/Rocky/Alma/Fedora)

The `.rpm` installs the node as a hardened systemd service under a dynamic user
with `CAP_NET_BIND_SERVICE` (so it can bind UDP 443), and provisions group keys
as a systemd credential. No Docker and no Python are required.

> The RPM binaries are built on a Rocky Linux 9 baseline (glibc 2.34), so they
> run on RHEL/Rocky/Alma 9+, recent Fedora, and any distro with glibc ≥ 2.34.
> Debian/Ubuntu is covered by the [Debian package](getting-started-deb.md).

## Prerequisites

- RHEL, Rocky Linux, AlmaLinux (9+) or Fedora, on `x86_64` or `aarch64`
- A root shell or `sudo`
- A UDP port reachable from the Internet (443 by default)

## Install

```bash
curl -fLO "https://github.com/albertsdk/hsync-bootnode/releases/latest/download/hsync-bootnode-VERSION-1.el9.ARCH.rpm"
sudo dnf install hsync-bootnode-VERSION-1.el9.ARCH.rpm
```

Replace `VERSION` and `ARCH` with the release you downloaded (for example
`1.0.0` and `x86_64`). To install a specific version, use that release's URL
(replace `latest/download` with `download/vX.Y.Z`).

To build from the checkout instead:

```bash
./compile.sh -t rpm        # host arch
./compile.sh -t rpm-all    # x86_64 + aarch64 (Docker)
```

## Configure and run

The package behaves exactly like the Debian package. Follow the steps in
[Debian package → Provision group keys](getting-started-deb.md#provision-group-keys-protected-buckets--private-node)
through
[→ Start the service](getting-started-deb.md#start-the-service), using
`sudo dnf upgrade hsync-bootnode-*.rpm` instead of `dpkg -i` to update.

## Next

- Prefer containers? [Installer script](getting-started-script.md) or
  [Docker](getting-started-docker.md).
- Running directly from a clone? [From source](getting-started-source.md).
