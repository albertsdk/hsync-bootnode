# Rust implementation of `hsync-bootnode` (future — v2)

**Not started.** This directory will hold the Rust/quinn implementation of the same
`boot/1` wire protocol (see [`../protocol-spec/boot-1.md`](../protocol-spec/boot-1.md)),
targeted at the full "thousands of handshakes/s" requirement.

The Rust port is an **additive v2**, not a prerequisite: the Python
implementation under `../python/` is the reference and is **complete and stable
(v1)**, so `hsync-bootnode` is fully functional today. Do not fork the spec here.

Target toolchain: **stable Rust 1.98+** (`rustup` stable channel); the crate
lives in this directory with its own `Cargo.toml` and `compile.sh` once the port
lands.