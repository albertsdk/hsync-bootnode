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
| `--private` | *(disabled flag)* | Private node: every frame must carry a valid `bucket_token`, for **every** bucket (not only `--protected-bucket`). Starting it with no group key fails fast (exit code 2). Environment variable form: `HSYNC_BOOTNODE_PRIVATE=1`. |
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
| `HSYNC_BOOTNODE_PRIVATE` | Same as `--private`; set to `1` to require a valid `bucket_token` on every frame. |
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

## Private node (authenticated bootstrap)

An **open** node serves every bucket, gating only the ones declared with
`--protected-bucket`. A **private** node gates *all* of them: that is the mode
for a bootstrap node that acts as the rendezvous point of one community instead
of a public service.

```bash
# every bucket needs a key; without any key the node refuses to start (exit 2)
hsync-bootnode run --host 0.0.0.0 --port 443 --private \
    --keys-fd 5 5< /etc/hsync-bootnode/group-keys
```

What `--private` changes:

| Aspect | Open node (default) | Private node |
|---|---|---|
| `register` / `refresh` / `query` | token required only for `--protected-bucket` | token required for **every** bucket |
| `leave` | anonymous | token required (an anonymous `leave` is silently dropped) |
| Bucket with no key loaded | served (public) | refused exactly like a wrong token |
| Startup with no group key | allowed | fails fast, exit code 2 |
| Rate limits | unchanged | unchanged (private mode never removes them) |

Notes:

- The wire format does not change: `bucket_token` is the same optional field the
  D11 protected buckets already use, so a client only needs the group key — no
  new protocol version and no client-side mode switch.
- Refusals stay uniform (`token_required`, then `rate_limited` with
  `retry_after`): a client cannot tell which buckets exist or are provisioned.
- Deployment: uncomment the `HSYNC_BOOTNODE_PRIVATE=1` example in the unit
  shipped with your OS (see "Deploying as a service"); the env-var form is
  exactly equivalent to the flag.

### Provisioning and key rotation

1. Mint one 64-hex group key per bucket (for example `openssl rand -hex 32`).
2. Write one `bucket=<key>` line per bucket to
   `/etc/hsync-bootnode/group-keys` (0640, root-owned) and start the node with
   `--private --keys-fd 5`.
3. Distribute the same key to the clients allowed in that bucket: they derive
   `HMAC-SHA256(key, "boot/1" || bucket)[:32]` and send only the derived token.

**Revocation is key rotation** — there is no per-peer account to disable.
Replace the key in the group-keys file, restart the node and redistribute the new
key; the previous tokens stop matching immediately. Treat a leaked group key as
a leaked node capability.

Trade-offs (by design, not defects):

- The token proves a *capability*, not an identity: whoever holds the key can
  register under any `cid`, or spoof a `leave` for a known pair. Peers verify
  the TLS fingerprint of the peers they contact, so a spoofed entry does not
  survive contact.
- Rate limits still apply to legitimate key holders; private mode is not a
  substitute for the anti-abuse limits.
- No account system and no persistence: routing table, keys and limits live in
  RAM only (see "Privacy model").

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
| `configuration error: private node without any group key …` | You started a private node (`--private` / `HSYNC_BOOTNODE_PRIVATE=1`) without provisioning a key: pass `--keys-fd` with at least one `bucket=<key>` line. |
| Client gets `token_required` | The bucket is gated (declared `--protected-bucket`, or every bucket on a private node) and the client's derived token is missing/wrong — check the group key on the client side. |
| Client gets `rate_limited` | A limit was exceeded (per-IP ~10 req/s, 5/min failed tokens, 5/min queries per (IP, bucket), 10/min registers per bucket); wait for `retry_after` seconds. |
| No UPnP mapping | Router without IGD, or mapping refused: the node keeps running stateless; publish a public UDP endpoint in another way or use `--no-upnp` to skip discovery entirely. |
| Need to see what the node is doing | Start with `--debug` (or `HSYNC_BOOTNODE_DEBUG=1`) for non-PII stderr diagnostics. |
