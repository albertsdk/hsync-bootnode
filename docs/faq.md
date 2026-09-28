# FAQ — hsync-bootnode

Operational questions about running the node and about the clients that connect
to it. For the CLI itself see [usage.md](usage.md).

## Why does my client abort with "certificate fingerprint … does not match the accepted pin"?

**Symptom.** A client that connected to the node before now stops with:

```text
ERROR: Bootnode <host>:<port> trust failed: certificate fingerprint <new>
does not match the accepted pin
```

**Why.** The client authenticates the node's **self-signed** certificate by
*pinning* its fingerprint: with `--bootnode-tofu` it remembers the first
fingerprint it sees for `<host>:<port>` and refuses any later change as a
possible man-in-the-middle. By default the node generates a **fresh identity at
every start** (the no-log invariant: the key lives only in RAM), so **restarting
the node changes its fingerprint** and every TOFU client then refuses it.

**Fix — operator (recommended).** Give the node a stable identity so the
fingerprint survives restarts, then distribute that fingerprint to clients:

```bash
# create on first run, reuse afterwards (0600 file, only the operator's key+cert)
hsync-bootnode run --identity /var/lib/hsync-bootnode/identity.pem
hsync-bootnode identity show --identity /var/lib/hsync-bootnode/identity.pem
```

Clients then pin it with `--bootnode-fingerprint <fingerprint>`.

**Fix — clients after an expected change.** If the new fingerprint is legitimate
(e.g. the operator just provisioned `--identity`, or rotated it), accept it
explicitly:

```bash
hsync p2p <host> -b <bucket> --bootnode-fingerprint <new-fingerprint>
```

Or, for a TOFU client, remove the stale pin so it is trusted again on the next
connection: delete the `<host>:<port>` entry from the client's trust store
(`bootnode_known_hosts.json` under `$XDG_STATE_HOME/hsync/`, or the path in
`HSYNC_BOOTNODE_TRUST_FILE`).

**Never** accept a fingerprint you cannot explain: a mismatch is precisely what
the pin protects against.

## Why does a client fail with `hostname … doesn't match DNSPattern(pattern=b'hsync-bootnode')`?

That client did **not** pin the node, so it verifies the certificate like any
public TLS server. The node is self-signed, and when it binds `0.0.0.0`/`::`
without `--public-host`, its certificate SAN falls back to the placeholder DNS
name `hsync-bootnode`, which never matches the address the client dials — so the
handshake is rejected (`Error: 298`). The node itself is reachable; certificate
verification is doing its job.

- **Client side** (supported trust model for a self-signed node): pin it with
  `--bootnode-tofu` or `--bootnode-fingerprint <fingerprint>`.
- **Operator side**: put the public name into the certificate SAN so clients
  that verify the hostname succeed:

```bash
hsync-bootnode run --identity /var/lib/hsync-bootnode/identity.pem \
    --public-host boot.example.net
```

`--public-host` is repeatable (add every name/IP that clients dial). Changing the
SAN requires regenerating the certificate, so the pinned fingerprint changes too
— see the rotation window above.

## The fingerprint changed after a restart — how do I avoid that?

Run the node with `--identity PATH` (see above). Without it the identity is
ephemeral and *any* restart or redeploy changes the fingerprint. With it, the
same fingerprint is reused until you deliberately rotate it.

```bash
hsync-bootnode identity rotate --identity /var/lib/hsync-bootnode/identity.pem
```

Rotation prints the new fingerprint; during the change window clients can be
given both fingerprints (the client accepts up to two pins), then moved to the
new one.

## I ran a *public* node — do clients need a fingerprint?

No: for a public, unprotected node clients may use `--bootnode-tofu` (or no pin
at all). Pinning is what matters when the identity must be *stable*, and it is
required for any node whose clients authenticate it.

## A client keeps logging "Waiting for peers to join" instead of exiting

If the trigger was the trust failure above, the client now **exits** with a fatal
exit code instead of waiting forever (the discovery lease loop stops on a pin
mismatch). If the client still waits, it means the node is reachable but no peer
is registered in the bucket yet — nothing is wrong: see the client's
[FAQ — p2p Mode](https://github.com/albertsdk/hsync-client/blob/main/docs/faq-p2p.md).

## Where can I read the pin the client stored?

On the client host, in `bootnode_known_hosts.json` under `$XDG_STATE_HOME/hsync/`
(or `~/.local/state/hsync/`), overridable with `HSYNC_BOOTNODE_TRUST_FILE`. It
maps `<host>:<port>` to the current fingerprint and its `updated_at` timestamp.
