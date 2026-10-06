# HSYNC Bootnode — Getting Started

`hsync-bootnode` is the Internet discovery node of the HSYNC sync network: it
tells P2P clients which peers are currently online without storing anything. It
speaks the `boot/1` protocol over QUIC (UDP, port 443 by default).

Pick **one** installation method below and follow it to a running node. The
methods are ordered from the simplest and most immediate to the most involved.

| # | Method | Best for | Guide |
| - | ------ | -------- | ----- |
| 1 | **Installer script** (`install.sh` via `curl`) | Least setup on a host with Docker: one command, TLS identity persisted | [Install with the script](getting-started-script.md) |
| 2 | **Docker / Compose** (manual) | You already manage containers, or want to build the image yourself | [Docker](getting-started-docker.md) |
| 3 | **Debian/Ubuntu package** (`.deb`) | A Debian/Ubuntu host without Docker, managed by systemd | [Debian package](getting-started-deb.md) |
| 4 | **RPM package** (`.rpm`) | A RHEL/Rocky/Alma/Fedora host without Docker, managed by systemd | [RPM package](getting-started-rpm.md) |
| 5 | **Windows installer** (`.exe`) | A Windows Server x64 host: per-machine install, registers a Windows service | [Windows installer](getting-started-windows.md) |
| 6 | **From source** (clone and run) | Development, or a host where you control the toolchain | [Run from source](getting-started-source.md) |

All methods result in the same node. The QUIC/UDP port must be reachable from
the Internet (443 is the default; ports below 1024 need elevated privileges —
the `.deb` systemd unit grants `CAP_NET_BIND_SERVICE`, the container binds an
unprivileged port internally).

## Requirements (all methods)

- UDP port 443 (or another port) reachable from the Internet
- Optional: a UPnP-capable router for zero-touch UDP port mapping (opt in with `--upnp`)

## How it works in one paragraph

A client registers itself with the node every 30 seconds and gets back an `ack`
with its observed public endpoint; its full endpoint candidate list is relayed
to querying peers. To find peers, clients query the node and receive a random
sample of the currently registered peers in their bucket. Everything lives in
RAM with a 60-second TTL: stop the process and every trace of your network is
gone.

## Next

- Run it as-is for a **public** rendezvous point, or with `--private` for the
  closed rendezvous point of a community — see
  [usage.md](usage.md#private-node-authenticated-bootstrap).
- Point clients at it with the `hsync p2p` bootnode argument (`hsync p2p <host>`)
  ([client p2p bootnode guide](https://github.com/albertsdk/hsync-client/blob/main/docs/p2p-bootnode.md)).
