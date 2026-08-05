# Architectural decisions — hsync-bootnode

Log of design decisions taken during implementation, especially where the
implementation deviates from `PIANO-hsync-bootnode-p2p.md` (workspace root).
The plan is the source of intent; this file records how intent became code.

| # | Decision | Rationale | Where |
|---|---|---|---|
| 1 | UPnP implemented with **pure-stdlib SSDP + SOAP** (`urllib`, raw XML) instead of the plan's `miniupnpc` library | No third-party binary dependency (D12 multi-platform matrix stays clean: Linux armv7/RPi included), full control over the no-log invariant, the zero-touch loop is best-effort by design and must degrade to stateless without crashing | `python/src/hsync_bootnode/upnp.py` |
| 2 | `leave` removes **every `(cid, bucket)` record regardless of group** | The `leave` frame carries no `group` field and a CID identifies one peer uniquely; a grouped register must not survive its own leave | `python/src/hsync_bootnode/routing.py:68` |
| 3 | CLI is a **Typer multi-command app** (`run` subcommand + top-level `--version`, bare invocation prints help) | Leaves room for future subcommands; the single-command Typer shape could not even parse `run` | `python/src/hsync_bootnode/cli.py:23` |
| 4 | CID pattern `^[A-Za-z0-9]{21}$` is a **local mirror** of `hsync_common.models.event.CID_PATTERN` until Fase 2 | The Python v1 must not depend on a not-yet-existing `hsync-common` protocol module; Fase 2 replaces the mirror with the SSOT import + drift test | `python/src/hsync_bootnode/protocol.py:41` |
| 5 | TLS identity is **generated per process** (never loaded from disk) | No-log by construction: no key/cert file to protect, and a fresh fingerprint per restart is acceptable because clients verify nothing beyond the transport | `python/src/hsync_bootnode/server.py:70` |
| 6 | Rate limiting uses **in-memory sliding windows** keyed by IP/(IP,bucket)/bucket, not a persistent store | Spec §5; nothing may be written to disk (D7), so limits restart with the process | `python/src/hsync_bootnode/ratelimit.py` |
