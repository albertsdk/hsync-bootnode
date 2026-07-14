# hsync-bootnode — Welcome

`hsync-bootnode` is the Internet discovery node of the HSYNC sync network: it
tells P2P clients which peers are currently online, without storing anything.
It runs an in-memory, no-log, zero-knowledge bootstrap service speaking the
`boot/1` protocol over QUIC (UDP port 443).

> **Status**: v1 (Python). The wire protocol is under active design — see
> `protocol-spec/boot-1.md`.

## How it works in one paragraph

A client registers itself with the node every 30 seconds and gets back an
`ack` with its public (NAT-mapped) endpoint. To find peers, clients query the
node and receive a random sample of the currently registered peers in their
bucket. Everything lives in RAM with a 60-second TTL: stop the process and
every trace of your network is gone.

## Requirements

- Python 3.12+ (Linux, macOS, Windows)
- UDP port 443 (or any other UDP port) reachable from the Internet
- Optional: a UPnP-capable router for zero-touch TCP port mapping

## Install (from source)

```bash
cd hsync-bootnode/python
python3 -m venv .venv
.venv/bin/pip install .
```

## Quick start (open mode — no protected buckets)

```bash
.venv/bin/hsync-bootnode run --host 0.0.0.0 --port 443
```

The node prints its effective configuration and the TLS certificate
fingerprint, then serves forever. For protected buckets, service deployment
(systemd/launchd/Windows) and the full option list, see the
[Usage reference](usage.md).

## Further reading

| Document | Content |
|---|---|
| [usage.md](usage.md) | CLI reference, protected buckets, keys provisioning, OS services |
| `protocol-spec/boot-1.md` | Wire protocol specification |
| `../PIANO-hsync-bootnode-p2p.md` | Roadmap (monorepo root) |
