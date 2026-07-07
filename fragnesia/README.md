# Fragnesia — Container Breakout via ESP-in-TCP Page-Cache Corruption

## Overview

The Linux kernel's XFRM ESP-in-TCP decapsulation path XORs AES-GCM keystream bytes into page-cache pages that were spliced from a regular file via `splice()`. By precomputing the nonce-to-keystream-byte mapping for a given AES-GCM key, the attacker can deterministically flip any byte in a page-cache page to any desired value, one byte at a time.

This gives an unprivileged user a **deterministic page-cache write primitive**: any file opened for reading can have its cached pages corrupted. The exploit overwrites the first 192 bytes of a setuid-root binary's ELF header with shellcode that calls `setgid(0) + setuid(0) + execve("/bin/sh")`.

**Discovery**: William Bowling (V12 team). **Patch**: [netdev 2026/05/13/79](https://lists.openwall.net/netdev/2026/05/13/79).

**Vulnerable kernels**: requires `CONFIG_INET_ESPINTCP` (ESP-in-TCP support). Present in most distro kernels since v5.x.

## Container Breakout Mechanism

1. **No privileges required**: `CAP_NET_ADMIN` is obtained via `unshare(CLONE_NEWUSER|CLONE_NEWNET)`, allowed by default Kubernetes seccomp profiles
2. **Read-only mount is sufficient**: the corruption happens in the kernel's shared page cache — `splice()` maps the file's pages directly into the TCP send buffer, and the XFRM ESP-in-TCP path XORs keystream bytes into them in-place
3. **Shared page cache**: when a container opens a host file through a `hostPath` mount (even read-only), it accesses the same page-cache pages as the host. Corrupting those pages affects every process that reads the file — including host processes
4. **No kernel offsets needed**: this is a pure data-corruption attack. No KASLR bypass, no gadgets, no version-specific offsets

## Attack Scenario

Many Kubernetes workloads mount the host filesystem read-only:

- **Node monitoring agents** (node-exporter, datadog-agent): `hostPath: /proc`, `/sys`, `/`
- **Log collectors** (fluentd, filebeat): `hostPath: /var/log`
- **Backup agents**: `hostPath: /`
- **Security scanners**: `hostPath: /`

The exploit corrupts a host setuid binary (e.g., `/usr/bin/su`) through the read-only mount. The next time any user runs `su` on the host, they get a root shell.

## Prerequisites

- Linux kernel with `CONFIG_INET_ESPINTCP=y` and `CONFIG_CRYPTO_USER_API_SKCIPHER=y`
- Docker or Kubernetes with seccomp profile that allows `unshare` (Kubernetes default), or `CAP_NET_ADMIN`
- Kernel must allow unprivileged user namespaces (`kernel.unprivileged_userns_clone=1`, the default on most distros)
- Target host must have a setuid-root ELF binary (e.g., `/usr/bin/su`) at least 192 bytes in size

## Files

| File | Description |
|------|-------------|
| `fragnesia_breakout.c` | Exploit adapted for container breakout |
| `Dockerfile` | Multi-stage build for the exploit container |
| `pod-breakout.yaml` | K8s pod with hostPath + unprivileged user (needs Unconfined seccomp) |
| `pod-breakout-netadmin.yaml` | K8s pod with hostPath + `CAP_NET_ADMIN` (works with default seccomp) |
| `docker-test.sh` | Docker-based demo script |
| `kind-config.yaml` | KinD cluster config (host kernel must be vulnerable) |

## Attack Paths

The exploit has two paths to obtain `CAP_NET_ADMIN`:

| Path | Container User | Capabilities | Seccomp | Typical Workload |
|------|---------------|-------------|---------|------------------|
| **User namespace** | Any (unprivileged) | None | `Unconfined` or pre-1.27 K8s | Monitoring agents, backup pods |
| **Direct NET_ADMIN** | root (UID 0) | `NET_ADMIN` | Default OK | Istio/Linkerd sidecars, CNI agents, VPN pods |

The user namespace path uses `unshare(CLONE_NEWUSER|CLONE_NEWNET)` to obtain `CAP_NET_ADMIN` without any container privileges. Docker's default seccomp profile blocks this, but many Kubernetes clusters (especially pre-1.27) run without seccomp.

The direct `NET_ADMIN` path works with Docker's default seccomp profile. Any pod running as root with `CAP_NET_ADMIN` — which is standard for service mesh sidecars and CNI agents — can exploit this.

## Reproduction — Docker

```bash
# Build the exploit container
docker build -t fragnesia:latest .

# Path 1: CAP_NET_ADMIN (works with default seccomp)
# Simulates a service mesh sidecar or CNI agent
docker run --rm --user 0:0 --cap-add NET_ADMIN \
    -v /:/hostfs:ro fragnesia:latest --hostfs /hostfs

# Path 2: Unprivileged user (needs seccomp=unconfined)
# Simulates a monitoring agent in a pre-1.27 K8s cluster
docker run --rm --user 1000:1000 \
    --security-opt seccomp=unconfined \
    -v /:/hostfs:ro fragnesia:latest --hostfs /hostfs

# On the host, verify the corruption
su    # drops to root shell without password

# Restore (page-cache only, no disk corruption)
echo 3 > /proc/sys/vm/drop_caches  # may not suffice; reinstall the package
apt-get install --reinstall util-linux
```

## Reproduction — Kubernetes

```bash
# Path 1: CAP_NET_ADMIN pod (more realistic)
kubectl apply -f pod-breakout-netadmin.yaml

# Path 2: Unprivileged pod with hostPath (needs Unconfined seccomp)
kubectl apply -f pod-breakout.yaml

# Exec into the pod and run the exploit
kubectl exec -it fragnesia-breakout -- /fragnesia_breakout --hostfs /hostfs

# Verify from a host shell:
su    # root shell
```

## Recovering from Corruption

The corruption is **page-cache only** — it does not modify the on-disk file. To restore the original binary:

```bash
# Drop all page caches (requires root)
echo 3 > /proc/sys/vm/drop_caches

# Or restart the host
```

## How the Primitive Works

```
            splice(target_fd, ..., pipe_fd)    TCP send via pipe
                     │                              │
                     ▼                              ▼
        ┌──────────────────────────┐    ┌───────────────────┐
        │  target file page cache  │    │   TCP send buffer  │
        │  ┌────────────────────┐  │    │  (zero-copy: skb   │
        │  │  ELF entry point   │  │────│   refs page-cache   │
        │  └────────────────────┘  │    │   pages directly)   │
        └──────────────────────────┘    └─────────┬─────────┘
                                                  │
                                                  ▼
                                        ┌───────────────────┐
                                        │   XFRM ESP-in-TCP  │
                                        │   decapsulation     │
                                        │                     │
                                        │   XORs AES-GCM     │
                                        │   keystream into    │
                                        │   page-cache page   │
                                        └───────────────────┘

Byte-by-byte corruption:
  1. splice() maps target file pages into a pipe, then into TCP send buffer
  2. XFRM SA configured with ESP-in-TCP encapsulation on loopback
  3. Craft ESP packet with chosen nonce → AES-GCM produces known keystream
  4. Keystream XORs with page-cache byte: original ⊕ stream = desired value
  5. Precompute nonce→stream mapping: for each target byte, find the nonce
     whose keystream XOR produces the desired output
  6. Send 192 ESP packets (one per byte) to corrupt the full ELF header
  7. Page cache is now corrupted — all future reads see the shellcode
```

## Mitigations

- **Remove unnecessary hostPath mounts** — most pods don't need host filesystem access
- **Use `readOnlyRootFilesystem: true`** — does NOT prevent this attack (corruption is in page cache, not on disk)
- **Restrict user namespaces**: set `kernel.unprivileged_userns_clone=0` (breaks some applications)
- **Use seccomp profiles** that block `unshare` with `CLONE_NEWUSER|CLONE_NEWNET`
- **Patch the kernel** — see [netdev patch](https://lists.openwall.net/netdev/2026/05/13/79)
- **Use `PodSecurity` admission** to block hostPath volumes (`baseline` or `restricted` profiles)
- **Disable ESP-in-TCP** if not needed: compile kernel without `CONFIG_INET_ESPINTCP`
