# LPE / Container Breakout Triage Criteria

## Must-Have Filters (reject if any fail)

### 1. Architecture: AMD64-relevant

The vulnerability must affect code that runs on x86_64. Reject CVEs that are specific to ARM, MIPS, PowerPC, RISC-V, S390, or other non-x86 architectures.

### 2. Core subsystem (shipped on servers)

The affected code must be in a subsystem that is compiled-in or loaded by default on mainstream server distributions (Ubuntu Server, RHEL/CentOS, Debian, Amazon Linux, etc.). Good subsystems include:

| Category | Examples |
|---|---|
| Networking core | netfilter/nftables, TCP/IP stack, Unix sockets, BPF, io_uring |
| Filesystem / VFS | ext4, overlayfs, tmpfs, pipe, epoll, inotify |
| Namespaces / cgroups | user namespaces, PID namespaces, cgroup v1/v2 controllers |
| IPC / scheduling | futex, mqueue, signals, sched |
| Memory management | mmap, userfaultfd, page cache, slab allocator |
| Device-agnostic core | TTY layer, devpts, procfs, sysfs |

**Reject**: GPU drivers, Wi-Fi/Bluetooth, sound subsystem, obscure HID drivers, architecture-specific crypto accelerators, staging drivers, or anything behind `CONFIG_` options that server distros don't enable.

### 3. Not denial-of-service only

The vulnerability must allow memory corruption, information disclosure of kernel memory, or control-flow hijack — not just a NULL pointer dereference panic or resource exhaustion. Pure DoS bugs (BUG_ON, panic, infinite loop, OOM) are out of scope.

## Signal Indicators (score 0-3 each)

These don't reject a CVE but indicate how likely it is to be exploitable for LPE.

### 4. Vulnerability class (0-3)

| Score | Class |
|---|---|
| 3 | Use-after-free, double-free, type confusion — objects with function pointers or exploitable fields |
| 2 | Heap buffer overflow, out-of-bounds write — can corrupt adjacent objects |
| 1 | Stack buffer overflow, integer overflow leading to undersized allocation |
| 0 | Out-of-bounds read (info leak only), uninitialised memory read |

### 5. Unprivileged reachability (0-3)

| Score | Reachability |
|---|---|
| 3 | Triggerable by a fully unprivileged user (no capabilities, no special group membership) |
| 2 | Requires capabilities available inside default containers (e.g. CAP_NET_RAW) or requires user namespaces (usually available) |
| 1 | Requires non-default capabilities (CAP_NET_ADMIN, CAP_SYS_ADMIN) but reachable from a privileged container |
| 0 | Requires root or capabilities not typically granted to containers |

### 6. Slab cache / object quality (0-3)

| Score | Slab characteristics |
|---|---|
| 3 | Freed object is in a generic `kmalloc-cg-*` cache (64-256 bytes), and the subsystem has known spray primitives with full content control |
| 2 | Generic `kmalloc-*` cache but larger sizes (512+), or good cache but limited spray options |
| 1 | Dedicated slab cache (`-S` flag) — cross-cache attacks needed, much harder |
| 0 | Object not heap-allocated, or size not controllable |

### 7. Race complexity (0-3)

| Score | Trigger reliability |
|---|---|
| 3 | No race condition — deterministic trigger (e.g. missing bounds check, wrong refcount decrement) |
| 2 | Race condition but wide window (milliseconds), winnable from userspace with `userfaultfd` or `FUSE` stalling |
| 1 | Tight race window (microseconds) requiring pthread spinning or repeated attempts |
| 0 | Extremely narrow race or requires winning multiple races in sequence |

### 8. Container relevance (0-3)

| Score | Container context |
|---|---|
| 3 | Reachable from within a default Docker/Kubernetes container with no special config — potential container breakout |
| 2 | Reachable from a container with common elevated permissions (privileged: false, but CAP_NET_RAW or hostNetwork) |
| 1 | Reachable only from a privileged container or with specific seccomp exceptions |
| 0 | Not reachable from any container context — host-only LPE |

## Scoring

- **Must-have filters**: all three must pass, or the CVE is skipped.
- **Signal score**: sum of indicators 4-8 (max 15).
  - **12-15**: High priority — likely exploitable, worth a full write-up and possible PoC.
  - **8-11**: Medium — exploitable with effort, worth an analysis note.
  - **4-7**: Low — probably not practical but could be interesting for chaining.
  - **0-3**: Skip — not worth further analysis.

## Triage Process

1. Clone or pull the `linux-vulns` git repo for the latest CVE YAML files.
2. For each new CVE (reverse chronological order):
   a. Read the one-line description and affected subsystem.
   b. Apply must-have filters — skip immediately if any fail.
   c. Read the fix commit diff to understand the vulnerability mechanics.
   d. Score against signal indicators.
   e. For score >= 8, create a `CVE-YYYY-NNNNN/analysis.md` with full details.
   f. Log all triaged CVEs (pass or fail) in `triage_log.md` for tracking.
