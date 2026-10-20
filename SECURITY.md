# Security Policy

## Supported Versions

Security fixes are applied to the latest version on the `main` branch.

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅        |
| < 1.0   | ❌        |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use GitHub's private vulnerability reporting:

1. Open the **Security** tab of this repository.
2. Click **Report a vulnerability** to start a private advisory.

Please include the affected version, how the node is deployed, steps to
reproduce, the impact, and any suggested mitigation. Allow a reasonable time for
a fix before any public disclosure. We aim to acknowledge reports within a few
days and to keep you informed of remediation progress.

## Security Model

- **No peer-data persistence** — the routing table is RAM-only and the process
  never writes peer data (IPs, CIDs, timestamps) to disk (no-log invariant).
- **Discovery, not data** — the bootnode only helps peers find each other; file
  data never passes through it.
- **Uniform refusals** — protected buckets return a uniform `token_required`
  refusal that never reveals whether a bucket exists; group keys are read once
  from a file descriptor (`--keys-fd`) or an operator-managed file
  (`--keys-file`, for service managers that cannot pass a descriptor, e.g.
  Windows), never from a path inside the sandbox on POSIX, and the node never
  writes them to disk.
- **Rate limiting** — in-memory per-IP/bucket sliding windows; over-limit
  requests receive `rate_limited` with `retry_after`. A node at its host-derived
  routing-table ceiling answers `overloaded` (capacity backpressure; advisory
  `retry_after`, not counted against the source) instead of mislabelling itself
  as a rate limit.
- **Supply chain** — the released container image is signed keyless with
  Sigstore/cosign by the release workflow, and `install.sh` verifies that
  signature against the workflow's OIDC identity before starting the node
  (an explicit `--no-verify` opts out). `--image-digest sha256:…` pins an exact
  image instead of a mutable tag.
- **Identity** — the TLS identity is a persistent ECDSA P-256 key+cert, created
  on first run and reused afterwards so the fingerprint is stable and can be
  pinned (ADR-0034/ADR-0037); it is the node's only on-disk artifact.
  `--identity PATH` overrides the path and `--ephemeral` keeps the identity in
  memory instead.

## Hardening Recommendations

- Run the node on UDP/443 via the packaged service unit and keep dependencies
  up to date. Install the container image through `install.sh` (or verify it
  with `cosign verify` yourself) so an unverified image is never started.
- If clients pin the fingerprint, keep the persistent identity (the default) or
  an explicit `--identity PATH`, and distribute the `sha256:<hex>` fingerprint
  out of band. Do not `--ephemeral` a node whose clients pin it.
- Keep `--debug` disabled in production: it is stderr-only but peer-aware.
