# Usage reference — hsync-bootnode

Reference for the CLI, the environment variables, the group-keys contract and
the OS service units. Installation and the open-mode quick start are on the
[welcome page](README.md).

## Command

The single command is `run` (plus the top-level `--version` flag):

```bash
hsync-bootnode run [OPTIONS]
hsync-bootnode --version
```

### `run` options

| Option | Default | Description |
|---|---|---|
| `--host` | `0.0.0.0` | Address to bind the QUIC/UDP listener to. |
| `--port` | `443` | UDP port (1–65535). 443 is the QUIC/HTTP3 default. |
| `--protected-bucket` | *(none)* | Bucket that requires a valid `bucket_token` (D11). Repeatable. Declaring a protected bucket without provisioning its key fails fast at startup (exit code 2). |
| `--keys-fd` | *(none)* | File descriptor carrying the group keys (see below). Environment variable form: `HSYNC_BOOTNODE_KEYS_FD`. |
| `--no-upnp` | *(disabled flag)* | Disable the zero-touch UPnP UDP mapping. |
| `--ttl` | `60` | Record TTL in seconds (1–3600). Peers refresh every 30 s, so the default 60 s matches the spec. Lower it for faster convergence in tests. |
| `--debug` | *(disabled flag)* | Emit non-PII diagnostics to stderr (opt-in). Environment variable form: `HSYNC_BOOTNODE_DEBUG=1`. |
| `--ready-file` | *(none)* | Write the process PID to this path once the listener is bound (readiness seam, contains no peer data). Environment variable form: `HSYNC_BOOTNODE_READY_FILE`. |
| `--no-rate-limit` | *(disabled flag)* | Disable rate limiting entirely (benchmark/test seam). Environment variable form: `HSYNC_BOOTNODE_NO_RATE_LIMIT=1`. Never enable in production — it removes the anti-abuse limits the spec requires (D11). |

### `--version`

Prints the version and the protocol, e.g.
`hsync-bootnode 0.1.0 (boot/1, Python v1)`, then exits.

## Environment variables

| Variable | Meaning |
|---|---|
| `HSYNC_BOOTNODE_KEYS_FD` | Same as `--keys-fd`; the env-var form is what service wrappers set. |
| `HSYNC_BOOTNODE_DEBUG` | Same as `--debug`; set to `1` for opt-in stderr diagnostics. |
| `HSYNC_BOOTNODE_READY_FILE` | Same as `--ready-file`; the readiness PID path used by tests/orchestrators. |
| `HSYNC_BOOTNODE_NO_RATE_LIMIT` | Same as `--no-rate-limit`; benchmark/test seam, never in production. |

## Group keys (`--keys-fd` / `HSYNC_BOOTNODE_KEYS_FD`)

Group keys provision **protected buckets** (D11). The process reads them ONCE
at startup from the given file descriptor — the key payload never touches a
path inside the node's sandbox and is never written to disk.

Line format (comments and blank lines are ignored):

```
# bucket=<hex-group-key>
shared=9f1c...
home=44ab...
```

Example with a systemd credential (fd 5):

```bash
hsync-bootnode run --protected-bucket shared --keys-fd 5 \
    5< /etc/hsync-bootnode/group-keys
```

Notes:

- Clients derive the same `bucket_token` from the group key with
  `HMAC-SHA256(key, "boot/1" || bucket)[:32]` and send only the derived token
  (64 lowercase hex chars) on `register`/`refresh`/`query`.
- Wrong or missing tokens are answered uniformly with `token_required` and
  rate-limited (5/min per IP → `rate_limited` with `retry_after`); the node
  never reveals whether a bucket exists.

## Privacy model (no-log)

- Peer data (IPs, CIDs, timestamps) lives only in RAM with the configured
  `--ttl` (default 60 s, max 3600 s).
- The TLS certificate is self-signed, generated at startup, and never
  persisted.
- Output goes to the console only; the shipped service units discard it
  (`/dev/null`).

## Diagnostics (debug mode)

The node is silent by design. For troubleshooting, `--debug` (or
`HSYNC_BOOTNODE_DEBUG=1`) enables **non-PII** diagnostics on stderr — frame
types, outcomes, rate-limit refusals and prune/lifecycle events, never IPs,
CIDs or fingerprints. It is off by default and does not write anything to
disk.

The `--ready-file`/`HSYNC_BOOTNODE_READY_FILE` seam writes the process PID to
the given path once the QUIC listener is bound (and removes it on graceful
shutdown). It carries no peer data and exists so tests and orchestrators can
await readiness deterministically.

## Deploying as a service

Ready-made units are in `packaging/`:

| OS | Unit | Install |
|---|---|---|
| Linux | `packaging/systemd/hsync-bootnode.service` | `sudo cp … /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now hsync-bootnode` — hardened (DynamicUser, syscall filter); group keys are read from a systemd credential. |
| macOS | `packaging/launchd/it.hsync.bootnode.plist` | `sudo cp … /Library/LaunchDaemons/ && sudo launchctl bootstrap system …` — group keys are exposed as fd 3 by the embedded shell wrapper. |
| Windows | `packaging/windows/hsync-bootnode-service.xml` | WinSW v2: rename `WinSW-x64.exe` to `hsync-bootnode-service.exe` next to the XML, adjust the venv path, then `.\hsync-bootnode-service.exe install` + `start`. |

Edit the executable paths inside each unit to the location of your venv.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `configuration error: protected bucket(s) without a group key …` | You declared `--protected-bucket` without provisioning its key: pass `--keys-fd`/`HSYNC_BOOTNODE_KEYS_FD` with a matching `bucket=<key>` line. |
| Client gets `token_required` | Bucket is protected and the client's derived token is missing/wrong — check the group key on the client side. |
| Client gets `rate_limited` | A limit was exceeded (per-IP ~10 req/s, 5/min failed tokens, 5/min queries per (IP, bucket), 10/min registers per bucket); wait for `retry_after` seconds. |
| No UPnP mapping | Router without IGD, or mapping refused: the node keeps running stateless; publish a public UDP endpoint in another way or use `--no-upnp` to skip discovery entirely. |
| Need to see what the node is doing | Start with `--debug` (or `HSYNC_BOOTNODE_DEBUG=1`) for non-PII stderr diagnostics. |
