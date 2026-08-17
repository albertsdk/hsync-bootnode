# hsync-bootnode — Python implementation (v1)

In-memory, zero-knowledge P2P bootstrap node for HSYNC, sharing the single wire
protocol `boot/1` (see [`../protocol-spec/boot-1.md`](../protocol-spec/boot-1.md)).

## Status

**v1 complete (Fase 1)**: QUIC listener (aioquic) with mandatory RETRY +
address-validation, in-memory TLS identity, rigid `boot/1` schemas, in-memory
routing table (TTL/prune/sample), sliding-window rate limits, protected
buckets (D11) with constant-time token compare, STUN-echo, zero-touch UPnP and
the no-log invariant enforced under a read-only filesystem test.

## Layout

```
python/
├── pyproject.toml
├── src/hsync_bootnode/
│   ├── __init__.py
│   ├── __main__.py       # python -m hsync_bootnode
│   ├── cli.py            # Typer CLI (run, --version, --keys-fd, ...)
│   ├── protocol.py       # boot/1 frame models + validators (pydantic extra="forbid")
│   ├── handler.py        # transport-agnostic core (routing + D11 + rate limits)
│   ├── server.py         # QUIC transport (aioquic), in-memory TLS identity
│   ├── routing.py        # in-memory routing table (TTL/prune/sample)
│   ├── ratelimit.py      # sliding-window rate limiters
│   ├── tokens.py         # bucket_token derive + constant-time compare
│   └── upnp.py           # zero-touch UDP mapping (SSDP + SOAP, best-effort)
└── tests/
    ├── test_scaffold.py   # fixtures / spec + schema positives/negatives
    ├── test_handler.py    # routing, TTL, D11, rate limits, STUN-echo
    ├── test_server.py     # QUIC loopback
    ├── test_upnp.py       # SSDP/SOAP shapes, stateless no-IGD
    ├── test_nolog.py      # zero-write invariant (read-only fs)
    └── test_cli.py        # CLI contract
```

## Run

```bash
python -m hsync_bootnode run --host 0.0.0.0 --port 443
```

## Build (standalone binary)

```bash
cd python
./compile.sh            # → dist/linux-amd64/hsync-bootnode (host standalone)
```

Binaries only — the Debian package is assembled at the repo root
(`../compile_deb.sh`). Protected buckets and keys provisioning, service
deployment and the full option list: [`../docs/usage.md`](../docs/usage.md).
Internal architecture:
[`../llm-wiki/architecture.md`](../llm-wiki/architecture.md).