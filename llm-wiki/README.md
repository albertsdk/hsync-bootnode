# HSYNC Bootnode — LLM Wiki

Internal, agent-optimized knowledge base for the `hsync-bootnode` project
(no-log, zero-knowledge P2P bootstrap node speaking `boot/1`).

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
| [`run.sh`](../run.sh) | Uniform "run after clone" entry point (checks the sibling `hsync-common`, creates the in-project venv, runs the node) — mirrors `hsync-server/run.sh` |
| Install/distribution | `install.sh` (Docker Compose installer), `compose.yaml`, `Dockerfile` + `Dockerfile.dockerignore` + `python/entrypoint.sh` (image, group keys as fd 3), `docker.sh` (source image build/lifecycle) |
| OS service units | `packaging/{systemd,launchd,windows}/` |
| End-user documentation | `docs/` (`getting-started.md` chooser + one `getting-started-<method>.md` per install method; `usage.md`/`faq.md` are the reference) |

## Hard invariants (read before touching any module)

1. **No-log**: the process NEVER writes peer data (IPs, CIDs, timestamps) to
   disk. The TLS identity is a persistent ECDSA P-256 key+cert kept **by default**
   (`run --identity PATH` overrides the XDG state path; `run --ephemeral` keeps
   it in memory instead) — the operator's own key+cert (ADR-0034/ADR-0037), never
   peer data, and the node's only on-disk artifact. Enforced by
   `python/tests/test_nolog.py` (read-only filesystem sandbox). Diagnostics
   come in two stderr channels: an **always-on**, peer-free operational one
   (`warn`/`error`, decisions #36) and the opt-in peer-aware `--debug` sink
   (decision #25); without `--debug` nothing peer-related leaves memory.
2. **RAM only**: the routing table lives in
   `python/src/hsync_bootnode/routing.py` and is never persisted. TTL 60 s,
   prune every 15 s, client refresh every 30 s.
3. **Rigid schema**: every `boot/1` frame model uses pydantic
   `extra="forbid"` — unknown/targeted fields make the frame invalid and it is
   silently dropped. The field domains are enforced too: `bucket_token` must be
   64 lowercase hex characters (`BucketToken`, `protocol.py`) and `connected`
   is bounded to `0..2^53` (`CONNECTED_MAX`), so a value that cannot exist in
   the key-derivation domain or a wire-bignumber is an invalid frame, not an
   unbounded storage/accounting event (decisions #44/#46).
4. **Protected buckets**: tokens are derived
   `HMAC-SHA256(key, "boot/1" || bucket)[:32]` hex, compared in constant time
   (`hmac.compare_digest`); refusals are uniform (`token_required`) and never
   reveal bucket existence. `--private` widens the same policy to every bucket
   (including `leave`): see `decisions.md` #22. `leave` ownership extends the
   same idea onto open buckets: a departure from an unknown source IP is
   silently ignored (decision #45).
5. **Zero backward compatibility**: breaking the wire contract means bumping
   the mandatory `protocol_version` (`boot/1`) and updating spec, fixtures,
   implementation and tests atomically.
6. **SSOT note**: the CID shape and the bucket-name rule are **imported** from
   `hsync-common` (`hsync_common.models.event.CID_PATTERN`,
   `hsync_common.path_validation.is_valid_bucket_name`), not re-declared locally;
   the boot/1 spec + fixtures stay the cross-language contract. The daemon also
   reuses `hsync_common.ssl_utils` for its TLS identity (see
   `decisions.md` #26 and hsync-common ADR-0033); ADR-0034/ADR-0037 define the
   persistent identity (`--identity`, `--ephemeral`, `identity show`/`rotate`)
   and the `sha256:<hex>` trust fingerprint.
