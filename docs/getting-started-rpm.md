# Getting Started — RPM package (RHEL/Rocky/Alma/Fedora)

The `.rpm` installs the node as a hardened systemd service under a dynamic user
with `CAP_NET_BIND_SERVICE` (so it can bind UDP 443), and provisions group keys
as a systemd credential. No Docker and no Python are required.

> The RPM binaries are built on a Rocky Linux 9 baseline (glibc 2.34), so they
> run on RHEL/Rocky/Alma 9+, recent Fedora, and any distro with glibc ≥ 2.34.
> Debian/Ubuntu is covered by the [Debian package](getting-started-deb.md).

## Prerequisites

- <img src="assets/os/redhat.svg" alt="Red Hat" width="16" height="16"> <img src="assets/os/fedora.svg" alt="Fedora" width="16" height="16"> RHEL, Rocky Linux, AlmaLinux (9+) or Fedora, on `x86_64` or `aarch64`
- A root shell or `sudo`
- A UDP port reachable from the Internet (443 by default)

## Install

```bash
curl -fLO "https://github.com/albertsdk/hsync-rendezvous/releases/latest/download/hsync-rendezvous-x86_64.rpm"
sudo dnf install hsync-rendezvous-x86_64.rpm
```

The URL always points to the **latest stable** release; use `aarch64` instead of
`x86_64` on ARM. To pin a version, use
`https://github.com/albertsdk/hsync-rendezvous/releases/download/vX.Y.Z/hsync-rendezvous-<version>-1.el9.<arch>.rpm`.

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
`sudo dnf upgrade hsync-rendezvous-*.rpm` instead of `dpkg -i` to update.
The optional
[second UDP port](getting-started-deb.md#optional-serve-a-second-udp-port)
drop-in applies unchanged.

## Next

- Prefer containers? [Installer script](getting-started-script.md) or
  [Docker](getting-started-docker.md).
- Running directly from a clone? [From source](getting-started-source.md).
