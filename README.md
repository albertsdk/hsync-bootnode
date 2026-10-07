<p align="center">
  <img src="docs/assets/hsync-logo-horizontal.svg" alt="HSYNC logo" width="300">
</p>

# HSYNC Bootnode

**HSYNC Bootnode** is the optional discovery node that lets HSYNC peers find
each other over the Internet when they are **not** on the same local network. It
is a stateless, no-log meeting point: it tells P2P clients which peers are
online without ever storing anything, speaking the `boot/1` protocol over QUIC
(UDP port 443). Think of it as an **address book, not a post office**: it helps
your devices find each other, and the file data always flows directly between
them.

> **Why it exists:** the [HSYNC Client](https://github.com/albertsdk/hsync-client)'s
> [p2p Mode](https://github.com/albertsdk/hsync-client/blob/main/docs/p2p-mode.md)
> discovers peers over mDNS on the local network. A bootnode extends that same
> mode across networks: same election, same transport, same peer-to-peer data
> plane — only discovery differs.

> **Status:** v1 **complete and stable** (Python + aioquic): packaged, tested,
> and the implementation clients currently talk to. A Rust/`quinn` port is
> planned as an **additive v2** for higher handshake throughput, not a
> prerequisite — this is a **multi-language** repository: one protocol, several
> implementations sharing the same spec and fixtures (see the
> [repository layout](CONTRIBUTING.md#repository-layout)).

> 👉 **Operational Advisory:** the bootnode is discovery-only — it never stores
> or relays file data. Provision protected buckets and pin its TLS fingerprint
> before exposing it to the Internet, and keep validated backups of any state you
> care about elsewhere.

---

[![License: BSD 3-Clause](https://img.shields.io/badge/License-BSD_3--Clause-brightgreen.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/albertsdk/hsync-bootnode)](https://github.com/albertsdk/hsync-bootnode/releases/latest)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![Rust 1.98+ (planned)](https://img.shields.io/badge/Rust-1.98+_(planned)-DEA584.svg)](rust/)
[![Status: v1](https://img.shields.io/badge/Status-v1-yellow.svg)](docs/README.md)

**Quick navigation:**
- **New to HSYNC?** Start with [What you can do](#what-you-can-do-with-hsync-bootnode) and the [Getting Started guide](docs/getting-started.md)
- **Deploying a node?** See the [Usage reference](docs/usage.md) and [Deploying as a service](docs/usage.md#deploying-as-a-service)
- **Writing an implementation?** Read the [`boot/1` specification](protocol-spec/boot-1.md)
- **Want to contribute?** See [Contributing](CONTRIBUTING.md)

---

## What you can do with HSYNC Bootnode

- **Extend p2p Mode across networks** — let devices that are not on the same
  LAN discover each other, with no central server holding the files.
- **Run a private, closed network** — start the node with `--private` and every
  frame is authenticated against a group key: no accounts, nothing stored.
- **Keep discovery stateless and no-log** — clients register and query
  candidates; the routing table is RAM-only with a 60-second TTL, and file data
  never passes through the node.

## What it is

HSYNC syncs files peer-to-peer without a central server. On a single local
network peers find each other with mDNS; when devices are spread across the
Internet they need a rendezvous point. The bootnode is exactly that, and nothing
more:

- Clients **register** their endpoint candidate list (the NAT-mapped public
  address and the local/LAN address) with the node every ~30 s and receive the
  observed endpoint back in an `ack`.
- Clients **query** the node and get a random sample of the peers currently
  registered in their bucket, each with the full candidate list the node relays
  verbatim; the requester tries the candidates, preferring one reachable from its
  own network.
- The routing table is **RAM-only** with a 60-second TTL: stop the process and
  every trace of the network is gone.

It is not a relay, not a storage node and not a control plane: file data always
flows directly between peers. See [How it works](docs/README.md#how-it-works-in-one-paragraph).

A node run as-is is a **public** rendezvous point for anyone who knows its
hostname. Started with `--private` it becomes the closed rendezvous point of a
single community instead: every frame is authenticated against a group key, there
is no account to create and nothing is stored — a **private, pseudonymous P2P
network over the Internet** whose file data still flows only between peers. See
[Private node](docs/usage.md#private-node-authenticated-bootstrap) and the
[privacy and anonymity model](docs/usage.md#privacy-and-anonymity-model).

## When you need it

**You need a bootnode when:**

* your P2P group spans different networks — home ↔ office, two branches, a laptop on mobile data — and you don't want a central server holding the files;
* you want a private, closed group: run the node with `--private` and every frame is authenticated against a group key, with no accounts to create and nothing stored.

**You don't need it when:**

* all your devices are on the same local network — plain `hsync p2p` discovers them via mDNS;
* your devices sync through an [HSYNC Server](https://github.com/albertsdk/hsync-server) (Server Mode), which already acts as their meeting point.

## Getting started

Pick an install method and follow it to a running node:

- [Installer script](docs/getting-started-script.md) — one `curl` command and the
  released container image;
- [Docker / Compose](docs/getting-started-docker.md) — manual container setup;
- [Debian package](docs/getting-started-deb.md) — `.deb` with a hardened systemd unit;
- [RPM package](docs/getting-started-rpm.md) — `.rpm` for RHEL/Rocky/Alma/Fedora;
- [Windows installer](docs/getting-started-windows.md) — per-machine service installer;
- [From source](docs/getting-started-source.md) — clone and run.

The [Getting Started](docs/getting-started.md) chooser compares the methods; point
clients at the node with the `hsync p2p` bootnode argument (`hsync p2p <host>`)
— see the client
[p2p bootnode guide](https://github.com/albertsdk/hsync-client/blob/main/docs/p2p-bootnode.md).

## Design invariants

- **No-log** — the process never writes peer data (IPs, CIDs, timestamps) to
  disk; the only on-disk artifact is the node's own TLS key+cert, kept by default
  (ECDSA P-256, `0600`) so its fingerprint is stable and pin-able across restarts.
  `--ephemeral` replaces it with an in-memory identity for read-only filesystems
  or throwaway nodes. Diagnostics on stderr come in two channels: an always-on,
  **peer-free** operational one (warnings/errors about the node itself) and the
  opt-in `--debug` operation log, the only one that can contain peer identity.
- **No telemetry** — the node never phones home: no usage data, analytics or
  statistics leave the process.
- **Zero-knowledge / protected buckets** — group tokens are HMAC-SHA256
  capabilities compared in constant time; refusals are uniform and never reveal
  whether a bucket exists.
- **Rigid schema** — every `boot/1` frame rejects unknown fields; malformed
  frames are silently dropped, never reinterpreted.
- **One wire protocol** — `protocol-spec/boot-1.md` is the single source of
  truth; every implementation must be byte-identical on the wire.

## Documentation

| Document | What it covers |
| -------- | -------------- |
| [Getting Started](docs/getting-started.md) | Choose an install method (installer script, Docker, `.deb`, source) and run the node |
| [Usage reference](docs/usage.md) | `run` options, environment variables, group keys, private nodes, privacy/security model, services, diagnostics |
| [`boot/1` specification](protocol-spec/boot-1.md) | Wire protocol — the single source of truth |
| [Internal wiki](llm-wiki/README.md) | Architecture, data models, decisions, hard invariants |
| [Benchmarks](bench/README.md) | L1–L5 measurement scope and methodology |
| [Black-box suite](tests/README.md) | Language-neutral wire/CLI contract tests |
| [Contributing](CONTRIBUTING.md) | Development setup, toolchain, tests and contribution guidelines |
| [Report an issue](https://github.com/albertsdk/hsync-bootnode/issues) | Open development and bug tracking |

## Associated Ecosystem Components

The other components of the HSYNC ecosystem:

- [HSYNC Main](https://github.com/albertsdk/hsync/blob/main/README.md) — Umbrella repository and project overview.
- [HSYNC Common](https://github.com/albertsdk/hsync-common/blob/main/README.md) — Shared library: data models, protocol, delta transfer, hashing.
- [HSYNC Server](https://github.com/albertsdk/hsync-server/blob/main/README.md) — Central sync hub: REST API, WebSocket relay, file storage.
- [HSYNC Client](https://github.com/albertsdk/hsync-client/blob/main/README.md) — CLI client: Server Mode and p2p Mode.
- [HSYNC Desktop](https://github.com/albertsdk/hsync-desktop/blob/main/README.md) — Desktop GUI front-end. *(in development)*
- [HSYNC Android](https://github.com/albertsdk/hsync-android/blob/main/README.md) — Android client app. *(in development)*

## Security & Vulnerability Reporting

The bootnode sits at the Internet edge, so security reports are taken seriously.
Please use GitHub's **Private Vulnerability Reporting** rather than a public issue:

👉 **[Report a vulnerability](https://github.com/albertsdk/hsync/security/advisories/new)**

See the ecosystem [Security Policy](https://github.com/albertsdk/hsync/blob/main/SECURITY.md)
for supported versions and hardening guidance.

## 🙋‍♂️ A note from the maintainer

This project was born out of the need for a system capable of replicating the contents of a folder from a PC or Android device to a NAS, primarily for backup purposes. There were already several solutions available for this purpose, but I could not find one that met all the requirements I ultimately needed. This led to the somewhat questionable idea of developing one from scratch and, in the process, gaining a deeper understanding of various programming languages, algorithms, frameworks, and so on.

Originally conceived as a hobby project, although it has been under constant development ever since, I believe I can now say that it has evolved to the point where its capabilities are comparable to those of commercial products, while also offering some distinctive features. As such, it could potentially be deployed in a variety of production environments as well.

HSYNC is a passion project developed in my spare time, currently primarily led by me. Please remember this when you interact with the project: everyone involved is doing our best to build something great together, but it is not a paid, full-time job for any of us.

## Disclaimer

> [!WARNING]
> **The bootnode exposes a network service.** Misconfiguration, software defects
> or unexpected conditions may expose your discovery metadata or make the node
> unavailable. **Use at your own risk**, run it in a controlled environment, and
> review the privacy model in the [Usage reference](docs/usage.md#privacy-and-anonymity-model).

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHOR OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY — including, without limitation, any direct, indirect, incidental, special, exemplary, or consequential damages, loss of data, or business interruption — WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This disclaimer supplements, and does not replace, the warranty disclaimer and limitation of liability provisions of the [BSD 3-Clause License](LICENSE), which govern this software.

## License

Distributed under the [BSD 3-Clause License](LICENSE).
