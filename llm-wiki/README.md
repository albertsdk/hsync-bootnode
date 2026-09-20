# hsync-bootnode — LLM Wiki

Internal, agent-optimized knowledge base for the `hsync-bootnode` project
(in-memory, zero-knowledge P2P bootstrap node speaking `boot/1`).

## Table of contents

| Document | Content |
|---|---|
| [architecture.md](architecture.md) | High-level system overview: layers, data flow, security model, target matrix |
| [data-models.md](data-models.md) | The `boot/1` frame models, nested types, shared validators and their relationships |
| [decisions.md](decisions.md) | Implementation decisions and deviations from the plan |

## Project snapshot (v1 — Python, Fase 1 complete)

| Artifact | Path |
|---|---|
| Wire-protocol specification (SSOT) | `protocol-spec/boot-1.md` |
| Shared protocol fixtures | `fixtures/bootnode-*.json` |
| Python implementation | `python/src/hsync_bootnode/` |
| [`compile_deb.sh`](../compile_deb.sh) | Root `.deb` assembler (`-l/--language`, `deb`/`deb-all`); per-language binary builds stay in their own directory | v1 |
| OS service units | `packaging/{systemd,launchd,windows}/` |
| End-user documentation | `docs/` |

## Hard invariants (read before touching any module)

1. **No-log**: the process NEVER writes peer data (IPs, CIDs, timestamps) to
   disk. TLS identity is in-memory, per-process. Enforced by
   `python/tests/test_nolog.py` (read-only filesystem sandbox).
2. **RAM only (D7)**: the routing table lives in
   `python/src/hsync_bootnode/routing.py` and is never persisted. TTL 60 s,
   prune every 15 s, client refresh every 30 s.
3. **Rigid schema (D3)**: every `boot/1` frame model uses pydantic
   `extra="forbid"` — unknown/targeted fields make the frame invalid and it is
   silently dropped.
4. **Protected buckets (D11)**: tokens are derived
   `HMAC-SHA256(key, "boot/1" || bucket)[:32]` hex, compared in constant time
   (`hmac.compare_digest`); refusals are uniform (`token_required`) and never
   reveal bucket existence. `--private` widens the same policy to every bucket
   (including `leave`): see `decisions.md` #22.
5. **Zero backward compatibility**: breaking the wire contract means bumping
   the mandatory `protocol_version` (`boot/1`) and updating spec, fixtures,
   implementation and tests atomically.
6. **SSOT note**: the CID pattern `^[A-Za-z0-9]{21}$` is currently a local
   mirror of `hsync_common.models.event.CID_PATTERN`
   (`python/src/hsync_bootnode/protocol.py:41`); Fase B replaces the mirror
   with the `hsync-common` import and adds `protocol/bootnode.py` to
   `hsync-common`.
