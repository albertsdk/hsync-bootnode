# hsync-bootnode — Welcome

`hsync-bootnode` is the Internet discovery node of the HSYNC sync network: it
tells P2P clients which peers are currently online, without storing anything.
It runs an in-memory, no-log, zero-knowledge bootstrap service speaking the
`boot/1` protocol over QUIC (UDP port 443).

> **Status**: v1 complete and stable (Python). The `boot/1` protocol is versioned
> and specified in `protocol-spec/boot-1.md`.

Run it as-is and it is a **public** rendezvous point. Run it with `--private` and
it becomes the closed rendezvous point of a single community: every frame is
authenticated against a group key, there is no account to create and nothing is
stored — a **private, pseudonymous P2P network over the Internet** whose file data
still flows only between peers. See
[Private node](usage.md#private-node-authenticated-bootstrap) and the
[privacy and anonymity model](usage.md#privacy-and-anonymity-model).

## How it works in one paragraph

A client registers itself with the node every 30 seconds and gets back an
`ack` with its public (NAT-mapped) endpoint. To find peers, clients query the
node and receive a random sample of the currently registered peers in their
bucket. Everything lives in RAM with a 60-second TTL: stop the process and
every trace of your network is gone.

## Requirements

- Python 3.12+ (Linux, macOS, Windows)
- UDP port 443 (or any other UDP port) reachable from the Internet — the 443
  default is privileged: run as root, grant `CAP_NET_BIND_SERVICE` (the systemd
  unit does), or use a port ≥ 1024 (e.g. `--port 8443`)
- Optional: a UPnP-capable router for zero-touch UDP port mapping

## Install (Debian/Ubuntu — `.deb`)

```bash
./compile_deb.sh -t deb        # host arch → dist/deb/hsync-bootnode_<ver>_<arch>.deb
sudo dpkg -i dist/deb/hsync-bootnode_*.deb
sudo systemctl enable --now hsync-bootnode.service
```

`./compile_deb.sh -t deb-all` cross-builds amd64/arm64/armhf via Docker +
`qemu-user-static`. The `-l/--language` flag (default `python`,
also `DEB_LANGUAGE`) selects which implementation the package embeds;
`rust` is rejected until that port exists. Protected buckets need a
group-keys file (never shipped in the package):

```bash
sudo install -m 0640 /path/to/group-keys /etc/hsync-bootnode/group-keys
```

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
fingerprint, then serves forever. For protected buckets, a **private node**
(every frame authenticated), service deployment (systemd/launchd/Windows) and
the full option list, see the [Usage reference](usage.md).

## Further reading

| Document | Content |
|---|---|
| [usage.md](usage.md) | CLI reference, protected buckets and private nodes, keys provisioning, privacy/security model, OS services |
| `protocol-spec/boot-1.md` | Wire protocol specification |
