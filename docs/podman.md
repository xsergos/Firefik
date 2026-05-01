# Podman compatibility matrix

firefik uses the Docker Engine SDK (`github.com/moby/moby/client`).
Podman ships a compatibility API (`podman system service`) that
emulates the Docker API on `/run/podman/podman.sock`. This document
captures which firefik features work through the Podman socket and
which don't (yet).

## Status at a glance

| Feature | Works? | Notes |
|---|---|---|
| `GET /containers/json` (list containers) | ✅ | Covered; firefik's `ListContainers` round-trips cleanly. |
| `GET /containers/{id}/json` (inspect) | ✅ | Container IPs, Labels, Status all populate correctly. |
| Event stream (`/events`) | ⚠️ | Emits `start`/`die`/`destroy` reliably. `rename` events are absent on older Podman (≤4.7); firefik silently falls back to periodic `Reconcile`. |
| Container labels | ✅ | firefik reads `firefik.*` labels identically to Docker CE. |
| `firefik.enable=true` + auto-apply | ✅ | Same behaviour; kernel rules installed on container start. |
| `firefik.template=...` expansion | ✅ | Template merge runs client-side, independent of Docker/Podman. |
| `firefik.policy=...` expansion | ✅ | Same as templates. |
| Unix socket auth (peer-cred) | ✅ | Podman unix socket supports `SO_PEERCRED`; `FIREFIK_ALLOWED_UIDS` works. |
| Rootless Podman | ❌ | firefik requires `NET_ADMIN` on the host netns; rootless Podman runs in a user namespace without host-netns access. |
| `firefik-admin doctor` | ⚠️ | The `docker-socket` check defaults to `/var/run/docker.sock`; pass `--docker-socket /run/podman/podman.sock` when running under Podman. |
| E2E compose suite | ❌ | `docker-compose.e2e.yml` uses Docker CE-specific features (`network_mode: host` on root namespace). A `podman-compose` port is not currently planned. |

Legend: ✅ confirmed working, ⚠️ works with caveats, ❌ not supported.

## How to run firefik against Podman

1. Enable the Podman API socket:

   ```bash
   systemctl enable --now podman.socket           # rootful
   # or: systemctl --user enable --now podman.socket (rootless, not supported)
   ls -la /run/podman/podman.sock
   ```

2. Point firefik at the Podman socket:

   ```bash
   docker run -d \
     -e FIREFIK_API_TOKEN="$(cat /etc/firefik/token)" \
     -v /run/podman/podman.sock:/var/run/docker.sock \
     --cap-add NET_ADMIN --cap-add NET_RAW \
     --network host \
     ghcr.io/<org>/firefik-backend:latest
   ```

   The mount aliases Podman's socket at Docker's canonical path;
   firefik's moby/moby client does not need to know which engine is
   on the other side.

3. Verify with `firefik-admin doctor --docker-socket /run/podman/podman.sock`.

## Test matrix

A CI matrix test is not yet shipped. The manual smoke flow:

| Test | Command |
|---|---|
| Container list | `curl -H "Authorization: Bearer $FIREFIK_API_TOKEN" http://localhost/api/containers \| jq '. \| length'` |
| Event-driven apply | `podman run -d --label firefik.enable=true --label firefik.firewall.web.ports=80 nginx:alpine` → verify `/api/rules` shows the container within 2s. |
| Remove event | `podman rm -f <name>` → verify kernel chain disappears on next reconcile. |

## Known gaps

- **No `podman-compose` support in CI.** Not currently planned.
- **Rootless Podman is permanently out of scope**: firefik needs
  `NET_ADMIN` on the host network namespace; rootless runtimes can't
  grant it by design.
- **`rename` events**: on Podman ≤ 4.7 firefik won't immediately
  re-apply after `podman rename`. Work-around: wait for the next
  periodic reconcile (`FIREFIK_DRIFT_CHECK_INTERVAL` or the 3-second
  startup safety-net reconcile).
