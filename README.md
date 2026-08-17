# hsync-bootnode

In-memory, zero-knowledge P2P bootstrap node for HSYNC (API and protocol under active design — see `protocol-spec/boot-1.md`).

> **Status**: v1 (Python, Fasi 0+1+1-bis). No-log/in-memory design; multi-language implementations sharing one wire protocol (`boot/1`).

## Layout (monorepo — multiple implementations of the SAME protocol)

| Path | Implementation | Status |
|---|---|---|
| [`protocol-spec/boot-1.md`](protocol-spec/boot-1.md) | Single wire-protocol specification | Draft |
| [`fixtures/`](fixtures/) | Shared protocol fixtures (single source for all languages) | Draft |
| [`python/`](python/) | v1 implementation — Python + aioquic (QUIC/UDP 443) | v1 (Fase 1) |
| [`packaging/`](packaging/) | OS service units — systemd / launchd / WinSW | v1 |
| [`llm-wiki/`](llm-wiki/) | Internal agent knowledge base (architecture) | v1 |
| [`docs/`](docs/) | End-user documentation (install, usage reference) | v1 |
| [`compile_deb.sh`](compile_deb.sh) | Root `.deb` assembler: `-l/--language` (default `python`; `rust`/`c` rejected until those ports exist), `deb`/`deb-all` targets | v1 |
| [`rust/`](rust/) | Future implementation — Rust + quinn | Not started |
| [`c/`](c/) | Optional future implementation — C | Not started |

## Rules (per project CLAUDE docs)

- One commit per repository; English-only commit messages (Conventional Commits).
- Docs-first: read `llm-wiki/` before touching code; dual-docs (`llm-wiki/` + `docs/`) stay in sync with any change.
- No-log by design: no writes to disk of IPs/timestamps; in-memory routing table only.
- Zero backward compatibility: rigid contracts, mandatory protocol versions, no shims/fallbacks.
