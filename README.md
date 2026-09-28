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
> implementations sharing the same spec and fixtures (see
> [Layout](#layout-monorepo--multiple-implementations-of-the-same-protocol)).

> 👉 **Operational Advisory:** the bootnode is discovery-only — it never stores
> or relays file data. Provision protected buckets and pin its TLS fingerprint
> before exposing it to the Internet, and keep validated backups of any state you
> care about elsewhere.

---

[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![Rust 1.98+ (planned)](https://img.shields.io/badge/Rust-1.98+_(planned)-DEA584.svg)](rust/)
[![Status: v1](https://img.shields.io/badge/Status-v1-yellow.svg)](docs/README.md)

**Quick navigation:**
- **New to HSYNC?** Start with [What it is](#what-it-is) and the [Getting Started guide](docs/README.md)
- **Deploying a node?** See the [Usage reference](docs/usage.md) and [Deploying as a service](docs/usage.md#deploying-as-a-service)
- **Writing an implementation?** Read the [`boot/1` specification](protocol-spec/boot-1.md)
- **Want to contribute?** See [Contributing](CONTRIBUTING.md)

---

## What it is

HSYNC syncs files peer-to-peer without a central server. On a single local
network peers find each other with mDNS; when devices are spread across the
Internet they need a rendezvous point. The bootnode is exactly that, and nothing
more:

- Clients **register** their public (NAT-mapped) endpoint with the node every
  ~30 s and receive it back in an `ack`.
- Clients **query** the node and get a random sample of the peers currently
  registered in their bucket.
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

## Design invariants

- **No-log** — the process never writes peer data (IPs, CIDs, timestamps)
  to disk. The TLS identity is in-memory and regenerated per process by default;
  `--identity PATH` is the single opt-in exception, persisting only the
  operator's own key+cert for a stable, pin-able fingerprint. Diagnostics on
  stderr come in two channels: an always-on, **peer-free** operational one
  (warnings/errors about the node itself) and the opt-in `--debug` operation log,
  the only one that can contain peer identity.
- **Zero-knowledge / protected buckets** — group tokens are HMAC-SHA256
  capabilities compared in constant time; refusals are uniform and never reveal
  whether a bucket exists.
- **Rigid schema** — every `boot/1` frame rejects unknown fields; malformed
  frames are silently dropped, never reinterpreted.
- **One wire protocol** — `protocol-spec/boot-1.md` is the single source of
  truth; every implementation must be byte-identical on the wire.

## Layout (monorepo — multiple implementations of the SAME protocol)

| Path | Implementation | Status |
|---|---|---|
| [`protocol-spec/boot-1.md`](protocol-spec/boot-1.md) | Single wire-protocol specification | v1 |
| [`fixtures/`](fixtures/) | Shared protocol fixtures (single source for all languages) | v1 |
| [`tests/`](tests/) | **Language-neutral** black-box suite (spawns the binary, wire-only) | v1 |
| [`bench/`](bench/) | L1–L5 benchmarks; L2/L3 language-neutral, L4 profiles the handshake, L5 the CPU saturation | v1 |
| [`python/`](python/) | v1 implementation — Python + aioquic (QUIC/UDP 443) | v1 |
| [`packaging/`](packaging/) | OS service units — systemd / launchd / WinSW | v1 |
| [`llm-wiki/`](llm-wiki/) | Internal agent knowledge base (architecture) | v1 |
| [`docs/`](docs/) | End-user documentation (install, usage reference) | v1 |
| [`compile.sh`](compile.sh) | Root build entry point: `native` / `rpi` / `deb` / `deb-all`, `-l/--language` (default `python`; `rust` rejected until that port exists) | v1 |
| [`rust/`](rust/) | Additive v2 port — Rust + quinn (not required by v1) | Not started |

## Quick start

The full install walkthrough (`.deb`, from source, protected buckets) lives in
[docs/README.md](docs/README.md). A minimal open-mode node from a source
checkout:

```bash
cd python
python3 -m venv .venv
.venv/bin/pip install .
.venv/bin/hsync-bootnode run --host 0.0.0.0 --port 443
```

The node prints its effective configuration and TLS certificate fingerprint,
then serves forever. Point the clients of a P2P group at the node — a first
contact trusts the printed fingerprint on first use, while a stable setup
persists the identity with `--identity` (so it survives restarts) and pins it:

```bash
# First contact: trust the fingerprint on first use.
hsync p2p boot.example.net -b mybucket -p /srv/hsync \
  --bootnode-tofu
```

```bash
# Stable setup: pin the fingerprint from `identity show`.
hsync p2p boot.example.net -b mybucket -p /srv/hsync \
  --bootnode-fingerprint YOUR_BOOTNODE_FINGERPRINT
```

Either way the client refuses an unpinned self-signed node, so one of the two
forms is required (`--insecure` is for loopback tests only).

See the [client guide — Sync across networks](https://github.com/albertsdk/hsync-client/blob/main/docs/p2p-bootnode.md)
for the client-side setup.

## Documentation

| Document | What it covers |
| -------- | -------------- |
| [Getting Started](docs/README.md) | Requirements, install (`.deb` / source), quick start |
| [Usage reference](docs/usage.md) | `run` options, environment variables, group keys, private nodes, privacy/security model, services, diagnostics |
| [`boot/1` specification](protocol-spec/boot-1.md) | Wire protocol — the single source of truth |
| [Internal wiki](llm-wiki/README.md) | Architecture, data models, decisions, hard invariants |
| [Benchmarks](bench/README.md) | L1–L5 measurement scope and methodology |
| [Black-box suite](tests/README.md) | Language-neutral wire/CLI contract tests |
| [Contributing](CONTRIBUTING.md) | Development setup, toolchain, tests and contribution guidelines |

### Associated Ecosystem Components

`hsync-bootnode` is an optional component of the HSYNC ecosystem:

- [HSYNC Main](https://github.com/albertsdk/hsync/blob/main/README.md) — Umbrella repository and project overview.
- [HSYNC Client](https://github.com/albertsdk/hsync-client/blob/main/README.md) — Sync client; the consumer of the `boot/1` protocol *(Stable)*.
- [HSYNC Common](https://github.com/albertsdk/hsync-common/blob/main/README.md) — Shared library; mirrors the `boot/1` contract for the Python side.
- [HSYNC Desktop](https://github.com/albertsdk/hsync-desktop/blob/main/docs/README.md) — Desktop client GUI front-end, exposes the bootnode setting *(in development)*.
- [HSYNC Android](https://github.com/albertsdk/hsync-android/blob/main/docs/README.md) — Android client app, mirrors the `boot/1` protocol *(in development)*.
- [HSYNC Server](https://github.com/albertsdk/hsync-server/blob/main/README.md) — Central synchronization hub (Server Mode).

## Security & Vulnerability Reporting

The bootnode sits at the Internet edge, so security reports are taken seriously.
Please use GitHub's **Private Vulnerability Reporting** rather than a public issue:

👉 **[Report a vulnerability](https://github.com/albertsdk/hsync/security/advisories/new)**

See the ecosystem [Security Policy](https://github.com/albertsdk/hsync/blob/main/SECURITY.md)
for supported versions and hardening guidance.

## A note from the maintainer

HSYNC is a passion project started by Alberto Basso. It is built in spare time,
with love. Please remember this when you interact with the project: everyone
involved is doing our best to build something great together, but it is not a
paid, full-time job for any of us.

## Disclaimer

> [!WARNING]
> **The bootnode exposes a network service.** Misconfiguration, software defects
> or unexpected conditions may expose your discovery metadata or make the node
> unavailable. **Use at your own risk**, run it in a controlled environment, and
> review the privacy model in the [Usage reference](docs/usage.md#privacy-and-anonymity-model).

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHOR OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY — including, without limitation, any direct, indirect, incidental, special, exemplary, or consequential damages, loss of data, or business interruption — WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This disclaimer supplements, and does not replace, Sections 6 ("Disclaimer of Warranty") and 7 ("Limitation of Liability") of the [Mozilla Public License 2.0](LICENSE), which govern this software.

## License

Distributed under the [Mozilla Public License 2.0](LICENSE).
