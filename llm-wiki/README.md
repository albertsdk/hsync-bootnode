# hsync-bootnode — LLM Wiki

Internal, agent-optimized knowledge base for the `hsync-bootnode` project
(in-memory, zero-knowledge P2P bootstrap node speaking `boot/1`).

## Table of contents

| Document | Content |
|---|---|
| [architecture.md](architecture.md) | High-level system overview: layers, data flow, security model, target matrix |
| [data-models.md](data-models.md) | The `boot/1` frame models, nested types, shared validators and their relationships |
| [decisions.md](decisions.md) | Implementation decisions |

## Project snapshot (v1 — Python, complete)

| Artifact | Path |
|---|---|
| Wire-protocol specification (SSOT) | `protocol-spec/boot-1.md` |
| Shared protocol fixtures | `fixtures/bootnode-*.json` |
| Python implementation | `python/src/hsync_bootnode/` |
| [`compile.sh`](../compile.sh) | Root build entry point (`native`/`rpi`/`deb`/`deb-all`, `-l/--language`); per-language binary builds stay in their own directory | v1 |
| OS service units | `packaging/{systemd,launchd,windows}/` |
| End-user documentation | `docs/` |

## Hard invariants (read before touching any module)

1. **No-log**: the process NEVER writes peer data (IPs, CIDs, timestamps) to
   disk. TLS identity is in-memory, per-process **by default**; `--identity PATH`
   is the single opt-in exception that persists only the operator's own key+cert
   (ADR-0034) for a stable, rotatable fingerprint. Enforced by
   `python/tests/test_nolog.py` (read-only filesystem sandbox). The opt-in
   `--debug` sink (decision #25) is stderr-only and may include the peer
   identity; without it nothing peer-related leaves memory.
2. **RAM only**: the routing table lives in
   `python/src/hsync_bootnode/routing.py` and is never persisted. TTL 60 s,
   prune every 15 s, client refresh every 30 s.
3. **Rigid schema**: every `boot/1` frame model uses pydantic
   `extra="forbid"` — unknown/targeted fields make the frame invalid and it is
   silently dropped.
4. **Protected buckets**: tokens are derived
   `HMAC-SHA256(key, "boot/1" || bucket)[:32]` hex, compared in constant time
   (`hmac.compare_digest`); refusals are uniform (`token_required`) and never
   reveal bucket existence. `--private` widens the same policy to every bucket
   (including `leave`): see `decisions.md` #22.
5. **Zero backward compatibility**: breaking the wire contract means bumping
   the mandatory `protocol_version` (`boot/1`) and updating spec, fixtures,
   implementation and tests atomically.
6. **SSOT note**: the CID shape and the bucket-name rule are **imported** from
   `hsync-common` (`hsync_common.models.event.CID_PATTERN`,
   `hsync_common.path_validation.is_valid_bucket_name`), not re-declared locally;
   the boot/1 spec + fixtures stay the cross-language contract. The daemon also
   reuses `hsync_common.ssl_utils` for its in-memory TLS identity (see
   `decisions.md` #26 and hsync-common ADR-0033); ADR-0034 adds the opt-in
   persistent identity (`--identity`, `identity show`/`rotate`) and the
   `sha256:<hex>` trust fingerprint.
