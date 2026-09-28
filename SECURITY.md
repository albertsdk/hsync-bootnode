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
  from a file descriptor (`--keys-fd`), never from a path inside the sandbox.
- **Rate limiting** — in-memory per-IP/bucket sliding windows; over-limit
  requests receive `rate_limited` with `retry_after`.
- **Identity** — the TLS identity is in-memory, regenerated per process by
  default; the opt-in `--identity PATH` persists only the operator's own
  key+cert (ADR-0034) so the fingerprint can be pinned.

## Hardening Recommendations

- Run the node on UDP/443 via the packaged service unit and keep dependencies
  up to date.
- If clients pin the fingerprint, use `--identity PATH` (stable, rotatable) and
  distribute the `sha256:<hex>` fingerprint out of band.
- Keep `--debug` disabled in production: it is stderr-only but peer-aware.
