# HSYNC Bootnode — Welcome

`hsync-bootnode` is the Internet discovery node of the HSYNC sync network: it
tells P2P clients which peers are currently online, without storing anything.
It runs a no-log, zero-knowledge bootstrap service speaking the `boot/1` protocol
over QUIC (UDP port 443): the routing table lives only in RAM, and the node's own
TLS key is its only on-disk artifact.

> **Status**: v1 complete and stable (Python). The `boot/1` protocol is versioned
> and specified in `protocol-spec/boot-1.md`.

Run it as-is and it is a **public** rendezvous point. Run it with `--private` and
it becomes the closed rendezvous point of a single community: every frame is
authenticated against a group key, there is no account to create and nothing is
stored — a **private, pseudonymous P2P network over the Internet** whose file data
still flows only between peers.

## How it works in one paragraph

A client registers itself with the node every 30 seconds and gets back an `ack`
with its observed public (NAT-mapped) endpoint; its full endpoint candidate list
is relayed to querying peers. To find peers, clients query the node and receive a
random sample of the currently registered peers in their bucket. Everything lives
in RAM with a 60-second TTL: stop the process and every trace of your network is
gone.

## Requirements

- Python 3.12+ (Linux, macOS, Windows)
- UDP port 443 (or any other UDP port) reachable from the Internet — the 443
  default is privileged: run as root, grant `CAP_NET_BIND_SERVICE` (the `.deb`
  and systemd unit do), or use a port ≥ 1024 (e.g. `--port 8443`)
- Optional: a UPnP-capable router for zero-touch UDP port mapping (opt in with `--upnp`)

## Start here

This guide is organised as a linear journey; pick the step that matches where
you are.

### 1. Choose your install method

Methods are ordered from the simplest and most immediate to the most involved:

- [Method 1 — Installer script](getting-started-script.md): `install.sh` via
  `curl`, released container image. **Best for a host with Docker, least
  setup.**
- [Method 2 — Docker / Compose](getting-started-docker.md): manual Compose,
  direct `docker run`, or a source image build. **Best if you manage
  containers.**
- [Method 3 — Debian/Ubuntu package](getting-started-deb.md): the node packaged
  as a `.deb` (hardened systemd unit, group keys as a systemd credential). **Best
  for a Debian/Ubuntu host without Docker.**
- [Method 4 — RPM package](getting-started-rpm.md): the node packaged as a
  `.rpm` (hardened systemd unit). **Best for a RHEL/Rocky/Alma/Fedora host
  without Docker.**
- [Method 5 — Windows installer](getting-started-windows.md): per-machine
  installer that registers the node as a Windows service (WinSW). **Best for a
  Windows Server host.**
- [Method 6 — From source](getting-started-source.md): clone and run with
  `run.sh` / Poetry, or a standalone binary. **Best for development or a host you
  control.**

Start from the [Getting Started](getting-started.md) chooser for a comparison
table that helps you pick.

### 2. Configure the node

- **Public node** — the default; no configuration.
- **Private node / protected buckets** — provision group keys; see
  [usage.md → Private node](usage.md#private-node-authenticated-bootstrap) and
  [usage.md → Group keys](usage.md#group-keys---keys-fd--hsync_bootnode_keys_fd).

### 3. Point clients at it

Pass the node to the client's `p2p` command (`hsync p2p <host>`; with the group
key for a private node). The client side is covered by the
[client p2p bootnode guide](https://github.com/albertsdk/hsync-client/blob/main/docs/p2p-bootnode.md).

### 4. Reference & internals

| Document | Content |
|---|---|
| [usage.md](usage.md) | CLI reference, protected buckets and private nodes, keys provisioning, privacy/security model, OS services |
| [faq.md](faq.md) | Operational FAQ: certificate pin/TOFU mismatches, stable identity, client-side recovery |
| [usage.md](usage.md#deploying-as-a-service) | Deploying as a service (systemd/launchd/Windows) |
| `protocol-spec/boot-1.md` | Wire protocol specification |
