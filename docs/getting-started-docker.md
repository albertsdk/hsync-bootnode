# Getting Started — Method 2: Docker / Compose (manual)

Use this method when you already manage containers, want to run the released
image with your own Compose setup, or want to build the image from source. For
the one-command installer instead, see
[Method 1: installer script](getting-started-script.md).

## Prerequisites

- <img src="assets/os/linux.svg" alt="Linux" width="16" height="16"> <img src="assets/os/apple.svg" alt="macOS" width="16" height="16"> Linux or macOS with Docker Engine or Docker Desktop running
- Docker Compose v2 (`docker compose version`)
- A UDP port reachable from the Internet (443 by default)

## Install

### With the released image (manual Compose)

Download `compose.yaml` from the release, create a private `.env` beside it, and
start it:

```dotenv
HSYNC_BOOTNODE_IMAGE=ghcr.io/albertsdk/hsync-bootnode:v1.0.0
HSYNC_BOOTNODE_IDENTITY=/var/lib/hsync-bootnode/identity.pem
# Private node / protected buckets (optional):
#HSYNC_BOOTNODE_KEYS_PATH=/secure/path/group-keys
#HSYNC_BOOTNODE_KEYS_FILE=/keys
#HSYNC_BOOTNODE_PRIVATE=1
```

The container binds the unprivileged UDP port `8443`; the host maps
`HSYNC_BOOTNODE_PORT` (default `443`) to it. Verify the image signature before
starting (the released image is signed keyless by the release workflow), then
start it:

```bash
chmod 600 .env compose.yaml
cosign verify \
  --certificate-identity-regexp '^https://github\.com/albertsdk/hsync-bootnode/\.github/workflows/release\.yml@refs/(heads|tags)/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "${HSYNC_BOOTNODE_IMAGE:-ghcr.io/albertsdk/hsync-bootnode:v1.0.0}"
docker compose config --quiet
docker compose pull
docker compose up -d
```

The [`install.sh`](getting-started-script.md) path runs this verification for
you (and can pin an exact digest with `--image-digest`).

### Quick container (diagnostic only)

A temporary `docker run` is useful only for a short smoke test:

```bash
docker run --rm -d --name hsync-bootnode-test \
  -p 443:8443/udp \
  --user "$(id -u):$(id -g)" \
  -v "$(pwd)/hsync-data:/var/lib/hsync-bootnode" \
  ghcr.io/albertsdk/hsync-bootnode:v1.0.0 run --port 8443
docker logs hsync-bootnode-test
docker stop hsync-bootnode-test
```

### Serve a second UDP port (optional)

The shipped Compose maps a single host UDP port to the container's internal
port. To also answer clients whose network blocks UDP 443, listen on a second
internal port and map it to another host port:

```yaml
command: ["run", "--host", "0.0.0.0", "--ports", "8443,5353"]
ports:
  - "443:8443/udp"
  - "53:5353/udp"
```

Both ports share one routing table; the container keeps using unprivileged
ports. See `--ports` in [usage.md](usage.md#run-options).

### Build the image from source

To build from source, follow the build steps in
[Contributing](../CONTRIBUTING.md).

`./docker.sh` also supports `stop`, `restart`, `status`, `logs -f`, `shell` and
`clean`; it persists the identity under `./hsync-data`. Environment variables
select the public port (`HSYNC_BOOTNODE_PORT`), private mode
(`HSYNC_BOOTNODE_PRIVATE=1`) and the group keys
(`HSYNC_BOOTNODE_KEYS_PATH=/path/to/group-keys`). Run `./docker.sh --help`.

## Verify the node is running

```bash
docker compose ps
docker compose logs | grep -i fingerprint
```

## Manage and update

```bash
docker compose logs -f
docker compose restart
docker compose down
docker compose up -d
```

`docker compose down` does not delete the identity directory. To update, pull the
new image tag (or rebuild with `./docker.sh build`) and bring the stack up again.

## Next

- Prefer the automated installer? [Installer script](getting-started-script.md).
- No Docker host? [Debian package](getting-started-deb.md) or
  [run from source](getting-started-source.md).
