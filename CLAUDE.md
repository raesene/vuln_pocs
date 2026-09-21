# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

This is a collection of Kubernetes and container security vulnerability proof-of-concept exploits used for demos and educational purposes. Each CVE directory is self-contained with its own README, manifests, and scripts.

## Architecture

Each PoC is an independent directory containing:
- A `README.md` with step-by-step exploit instructions
- Kubernetes YAML manifests (pods, services, RBAC, network policies, etc.)
- Shell scripts where automation is needed
- Optional `kind-config.yaml` for local cluster setup

There is no build system, test suite, or shared code between PoCs.

Work-in-progress PoCs live in `work_in_progress/CVE-YYYY-NNNNN/` until they are confirmed working, then move to the top-level.

## Test Infrastructure

### Test server

The test server is at `192.168.41.108`, accessible via SSH as user `rorym`. Use this host for building custom kernels and running Firecracker VMs.

**All vmm commands that mutate state require `sudo`** (`create`, `start`, `stop`, `delete`, `ssh`, ...). Only read-only commands (`list`, `image list`, `kernel list`) work without it. Without sudo, `vmm start` fails at the SSH-key injection step with a misleading `failed to setup loop device` mount error that looks like a system-wide loop-device problem — it isn't. Also never run vmm under `sudo strace`: the state json gets rewritten root-owned (`root:root 0600`) and the VM becomes invisible and unmanageable to `rorym`'s vmm.

Details on how to use the vmm tool are available in the skill located https://github.com/raesene/baremetalvmm/tree/main/skills/vmm-usage

### VM isolation (critical)

**Never run kernel exploit PoC development on the test server's host OS.** Always use Firecracker VMs via the `vmm` tool. VMs provide isolation and can be rebuilt trivially if the kernel panics. Use `vmm console <vm> --follow=false --full` to capture serial console output including kernel panics. Set `panic=0` + `panic_on_oops=1` at runtime so the VM halts on crash without rebooting.

### Firecracker VM workflow

1. Build a custom kernel with `build-kernel.sh` (see CVE-2026-43503 for the template) — downloads kernel source, applies Firecracker base config, enables exploit-specific CONFIG options
2. Create VM: `vmm create --kernel <kernel-name> <vm-name>`
3. SSH in for compilation and testing
4. For K8s clusters: `vmm cluster create --kernel <kernel-name> <cluster-name>` — note that Flannel or hostNetwork may be needed (Cilium can CrashLoop on non-standard kernels)

### iximiuz Labs playgrounds

Used for container-level PoCs (runc, containerd). The `docker` playground does **not** have GCC pre-installed — install it first:
```
labctl ssh $PLAYGROUND_ID --user root -- 'apt-get update -qq && apt-get install -y -qq gcc'
```
The playground user is `laborant` (not the local username), home dir is `/home/laborant/`.

## Common Tools and Patterns

- **This workspace is aarch64**: x86_64-only code (inline asm like `mfence`) fails to assemble locally. Use `gcc -fsyntax-only` for local syntax checks; do real builds on the test server or in a Firecracker VM
- **Sandboxed file analysis is confined to the repo root**: files outside the workspace can't be read by in-sandbox analysis tools, and the doc indexer skips `.c`/`.h`/Makefile by default — copy external material into the repo first (e.g. a `reference/` dir) and analyse it there
- **curl in this environment**: inline `curl ... | parser` in the shell is blocked; use the file pattern `curl -s -o /tmp/x URL` and parse the file in a separate step
- **Kernel CVE research sources**: NVD's CVE pages are JS-rendered and fetch as an empty shell — use the NVD REST API instead (`curl -s -o /tmp/x.json 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>'`). For Linux kernel CVEs the kernel CVE project JSON is better: `https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published/<year>/<CVE>.json` gives exact affected version ranges and fix commits in one hit
- **git.kernel.org cgit tip**: the `refs/?id=<sha>` view ignores the id and lists every repo tag — useless for tag-containment queries; don't burn retries on it
- **Docker-in-VM interactive demos**: `docker run` needs `-i` for an exploit's stdin relay (without it, stdin isn't attached and the relay immediately closes its socket half). The `security-rootfs` bash prompt theme eats buffered stdin during shell startup — stagger piped commands with `sleep`s after the shell connects, or use the plain `rootfs` image for clean relays
- **KinD (Kubernetes in Docker)** is the primary local cluster tool: `kind create cluster --config kind-config.yaml`
- **kubectl** is used for all cluster interaction — applying manifests, exec'ing into pods, checking logs
- **kubectl proxy** is frequently used to expose the API server locally for curl-based exploits
- Several PoCs exploit TOCTOU (time-of-check/time-of-use) race conditions and may require multiple attempts
- **Compiled C race helpers** are needed for tight TOCTOU windows (e.g., CVE-2025-31133). Bash loops are too slow for sub-millisecond races — use pthreads with `sched_yield()` and `usleep()` instead
- For runc-level PoCs, the OCI config must **not** mount `/dev` as tmpfs — otherwise runc uses the tmpfs `/dev/null` (which the race can't reach from outside the mount namespace). Docker always adds `/dev` tmpfs, making Docker-based runc race exploits significantly harder
- For runc race PoCs, the container's own process args should perform the exploit action (e.g., `"args": ["sh", "-c", "echo PAYLOAD > /proc/sys/kernel/core_pattern"]`), not `runc exec` after the fact — the race window is during `runc run`/`runc create`, and masking is already applied by the time `exec` runs
- **Docker seccomp vs Kubernetes**: Docker's default seccomp profile blocks `unshare(CLONE_NEWUSER)`, which many kernel exploits need for unprivileged `CAP_NET_ADMIN` via user namespaces. Use `--security-opt seccomp=unconfined` when testing with Docker. Kubernetes does **not** apply a seccomp profile by default in most clusters (only clusters with `--seccomp-default` or explicit `RuntimeDefault` pod annotations), so the same exploits work without modification in K8s. For Docker, also test with `--cap-add NET_ADMIN` as a second attack path — many real-world pods (service mesh sidecars, CNI agents) run with this capability

## Container Breakout PoC Pattern (page-cache family)

The page-cache corruption exploits (PeditCow, Fragnesia, DirtyClone, CopyFail) all follow a standardised structure. Use this when creating new breakout PoCs:

### File structure
```
CVE-YYYY-NNNNN/
  exploit.c (or <name>_breakout.c)
  Dockerfile                    # multi-stage static build
  docker-test.sh                # end-to-end Docker test
  pod-breakout.yaml             # unprivileged user ns path (seccomp=unconfined)
  pod-breakout-netadmin.yaml    # CAP_NET_ADMIN path (works with default seccomp)
  kind-config.yaml              # KinD cluster with hostPath mount
  README.md
```

### Two attack paths

Every breakout PoC must support two privilege-escalation paths:
1. **Unprivileged user namespace** — `unshare(CLONE_NEWUSER|CLONE_NEWNET)` to get `CAP_NET_ADMIN`. Needs `seccomp=unconfined` in Docker, works by default in K8s (pre-1.27).
2. **CAP_NET_ADMIN directly** — works with default seccomp. Covers real-world pods like service mesh sidecars and CNI agents.

### Common C code patterns

- **Namespace fallback**: try `unshare(CLONE_NEWUSER|CLONE_NEWNET)` then fall back to `unshare(CLONE_NEWNET)` then direct `CAP_NET_ADMIN`
- **Container detection**: check `/proc/1/cgroup` for `docker`/`kubepods`/`containerd` (not `/.dockerenv` which false-positives in VMs with Docker installed)
- **Host filesystem auto-detection**: probe `/hostfs`, `/host`, `/rootfs`, `/host-root`, `/mnt/host`
- **Suid binary search**: scan standard paths (`/usr/bin/su`, `/usr/bin/passwd`, etc.) with configurable prefix for hostPath mounts
- **Static build**: `gcc -O2 -Wall -Wextra -static -o exploit exploit.c`

### Dockerfile pattern
```dockerfile
FROM ubuntu:24.04 AS builder
RUN apt-get update && apt-get install -y gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY exploit.c /build/
RUN gcc -O2 -static -o /build/exploit /build/exploit.c

FROM ubuntu:24.04
COPY --from=builder /build/exploit /exploit
RUN chmod +x /exploit
USER 1000
ENTRYPOINT ["/exploit"]
```

## Kernel Heap Exploit Techniques (CVE-2026-23111)

- **Slab defragmentation** before freeing the victim object: spray filler objects to exhaust free slots in the target slab cache, so the freed victim slot is the first available for reclamation. Without this, sprays compete with many existing free slots and reclamation is unreliable
- **Table userdata** (`NFTA_TABLE_USERDATA`) is the best nftables heap spray primitive for `kmalloc-cg-128` — full content control from byte 0, correct GFP flags (`GFP_KERNEL_ACCOUNT`). `msgsnd` goes to a separate bucket slab; `setxattr` has a 40-byte header; `add_key` uses non-accounted GFP flags
- **ret2dir (physmap)**: `mmap` a page, read `/proc/self/pagemap` for the physical address, compute `page_offset_base + phys_addr` for the kernel direct-map alias. Gives a user-controlled page at a kernel virtual address — bypasses SMAP without needing a stack pivot or ROP chain. Requires readable pagemap (default in VMs, restricted in containers)
- **`modprobe_path` overwrite**: After gaining arbitrary write (via ret2dir + a memcpy gadget), overwrite the kernel's `modprobe_path` string, then execute a file with unknown magic bytes — the kernel runs the attacker's script as root via `call_usermodehelper`
- **Gadget selection for nftables UAF**: The `nft_expr_ops.eval` function pointer is called with `(expr, regs, pkt)` where `expr` points to attacker-controlled data. Functions that read parameters from their first argument (like `crypto_akcipher_sync_post` which does `memcpy(dst, src, len)` from struct fields) make effective "call-oriented" gadgets without needing ROP
- **SMAP and ZERO_SIZE_PTR**: `ZERO_SIZE_PTR` (address 16) is a userspace address — SMAP blocks kernel code from dereferencing it. Use physmap (kernel direct-map) addresses instead when the kernel needs to read/write through attacker-supplied pointers
- **Firecracker VM testing**: Use `vmm console <vm> --follow=false --full` to capture serial console output including kernel panics. Set `panic=0` + `panic_on_oops=1` at runtime so the VM halts on crash without rebooting

## Cross-Cache Exploitation Lessons (CVE-2026-46242)

- **SLAB_TYPESAFE_BY_RCU** on filp slab requires TWO RCU grace periods before a page reaches the buddy allocator — factor this into cross-cache reclamation timing
- **kfree_rcu** vs plain kfree matters: `kfree_rcu` blocks immediate reclaim (6.12.85+), plain `kfree` in earlier kernels allows immediate reclaim
- **Slab defrag**: must be done BEFORE the target free, not after — spray filler objects to exhaust free slots so the freed victim slot is the first available
- **SLAB_CPU_PARTIAL** sysfs value is objects, not slab/page count — divide by objects-per-slab to get the actual slab count
- **Memory pressure** (mmap MAP_POPULATE) partially helps cross-cache but is unreliable in large free-page pools — prefer targeted defrag

## io_uring Exploit Development Lessons (CVE-2026-46274)

- **IOSQE_ASYNC** prevents hashing in io-wq (deferred file resolution means file=NULL at hash time)
- **Buffered writes on tmpfs** complete inline — never reach the io-wq pending list
- Every assumption about io-wq behavior must be **smoke-tested with bpftrace** before building the full trigger
- O_DIRECT on ext4 reaches io-wq but writes may not be hashed (flags=0x0) — root cause unresolved

## Ptrace / Credential-Disclosure Logic Bugs (CVE-2026-46333)

Template for **pure kernel logic bugs** (authorization bypasses), which are far cheaper to
exploit than memory-corruption bugs:

- **No slab grooming / KASAN / ROP.** The exploit is a retry loop around one syscall and wins
  in single-digit to low-double-digit attempts.
- **Root-cause shape:** `__ptrace_may_access()` skipped the dumpable check when `task->mm ==
  NULL`, and `do_exit()` clears `mm` (`exit_mm()`) before `files` (`exit_files()`).
  `pidfd_getfd()` then steals any fd from the dying process. The window is entered on *every*
  `do_exit()`.
- **Race recipe:** `fork`/`exec` the victim → `pidfd_open()` → `SIGKILL` → hammer
  `pidfd_getfd()` over fds 3..N from 2 hammer threads while retrying spawns. The victim must
  have dropped to our uid/gid and still hold a privileged fd.
- **Victims where the attacker is the parent** (so Yama `ptrace_scope=1` does not help):
  `chage -l <self>` (setgid shadow → `/etc/shadow`), `ssh-keysign` (setuid root → host keys),
  `pkexec` (root-authenticated D-Bus → root RCE). Non-parent victims (`accounts-daemon`) need
  `ptrace_scope=0`.
- `chage -l` only lists the *invoking* user's own entry; resolve the passwd name for the run
  uid (fallback: parse `«chroot»/etc/passwd`).

**Container breakout from the same bug**

- `pidfd_getfd` is allowed by Kubernetes' default seccomp (no profile) but **blocked by
  Docker's default seccomp** unless the container has `CAP_SYS_PTRACE` → Docker needs
  `--security-opt seccomp=unconfined`; K8s default needs nothing.
- A non-root container process starts with an **empty effective capability set**, so
  `securityContext.capabilities.add` alone does nothing. To `chroot()`, use a *file* capability
  (`setcap cap_sys_chroot+ep`) **plus** the bounding-set add — same trick as OVSwrap's
  `cap_net_admin+ep`.
- Breakout without `hostPID`: mount host `/` read-only at `/hostfs`, `chroot("/hostfs")`, and
  exec the host's setgid/setuid binary so it operates on host paths. Run the pod as the uid the
  **host's** passwd maps to (e.g. 1000 → `ubuntu`) so the victim drops to a matching uid.
- `vmm cluster create --kernel security-kernel` works with Cilium out of the box
  (`CONFIG_BPF_JIT=y`); no CNI surgery needed.
- Docker builds inside a vmm guest are very slow behind the container bridge — use
  `docker build --network host`.
- **Always run a patched-kernel control** before calling a race bug proven: same exploit on the
  post-fix kernel must fail (`security-kernel-tee`, 6.12.94, contains the CVE-2026-46333 fix).

## Custom Kernel Building

For exploits requiring specific kernel configs, use `build-kernel.sh` scripts (see CVE-2026-43503 as template):
1. Download kernel source from kernel.org
2. Apply Firecracker base config from `firecracker-microvm/firecracker` repo
3. Enable exploit-specific CONFIG options via `scripts/config --enable`
4. **Verify critical CONFIG options in `.config` after `make olddefconfig`** — options drop silently when their dependencies aren't met (e.g. `CONFIG_DEBUG_INFO_BTF` vanishes if pahole isn't detected; the kernel then boots without `/sys/kernel/btf/vmlinux`). Hard-fail the build if a required option is missing.
5. Build with `make -j$(nproc) vmlinux`
6. Install to `/var/lib/vmm/images/kernels/` on the test server — **run the build script with `sudo`** (or sudo the final `cp`), the kernels dir is root-owned and a 15-minute build otherwise dies at the last step

**The install step needs root.** `/var/lib/vmm/images/kernels/` is root-owned, so
`build-kernel.sh` must `sudo` its `mkdir`/`cp`/`tee` (all scripts now do this via a `$SUDO`
prefix). Otherwise the build spends 15 minutes compiling and then fails at the very last step.

**Reuse a pre-patch kernel instead of rebuilding when you can.** Check the build date (or
kernel version) before compiling: `strings -a /var/lib/vmm/images/kernels/<k> | grep -m1 "Linux
version"` or read the `.meta`. A prebuilt kernel built *before* the upstream fix commit is
already vulnerable — e.g. `security-kernel` (6.12.87, built 2026-05-08) predates the
CVE-2026-46333 fix `31e62c2` (2026-05-13), so no custom build was needed. Keep a post-fix
kernel (`security-kernel-tee`) as the negative control.

Required CONFIG options by exploit family:
- **PeditCow (CVE-2026-46331)**: `CONFIG_NET_ACT_PEDIT`, `CONFIG_NET_CLS_BASIC`, `CONFIG_NET_CLS_MATCHALL`, `CONFIG_NET_EMATCH_META`
- **Fragnesia**: all PeditCow configs + `CONFIG_INET_ESPINTCP`, `CONFIG_INET6_ESPINTCP`
- **DirtyClone (CVE-2026-43503)**: `CONFIG_INET_ESP`, `CONFIG_NETFILTER_XT_TARGET_TEE`, XFRM/IPsec stack
- **nftables UAF (CVE-2026-23111)**: nftables + `CONFIG_CRYPTO_USER` (for crypto_akcipher gadget)
- **ip6frag escape (CVE-2026-53362)**: `CONFIG_DEBUG_INFO_BTF` + `CONFIG_PAHOLE_HAS_SPLIT_BTF` (BTF offset resolution), `CONFIG_KALLSYMS_ALL` (data symbols for the in-process kallsyms parser), `CONFIG_USER_NS`; `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` must stay **off**. Note: `CONFIG_SPLICE` no longer exists in 6.12 — splice is unconditionally built, so don't enable or verify for it

## Porting the `manizada` AI-Harness LPE PoCs (Linux LPE quartet)

The DirtyAH6 (CVE-2026-80844), TUNderflow (CVE-2026-81000), PPPoEject (CVE-2026-68121) and
DiagSpill (CVE-2026-74469) PoCs from <https://heyitsas.im/posts/lpe-quartet/> share a common
shape and porting workflow. Lessons that save a lot of time next session:

**Triage the reachability path, not just the stable fix.** A backported stable fix does not
mean an exploit is reproducible on that kernel. TUNderflow's fix is in 6.12.109, but its
exploit drives the bug through `IFLA_NETKIT_HEADROOM`, a UAPI that only exists from **6.14** —
so it is unreachable on *any* 6.12 (a KASAN 6.12.108 run produced no OOB at all). Before
building, check that the UAPI/feature the PoC uses exists in your kernel. 6.12 fix map:
DirtyAH6 → 6.12.108, TUNderflow → 6.12.109, PPPoEject → 6.12.101, DiagSpill → 6.12.103.
Existing kernels that already fit: `security-kernel`/`fragnesia-kernel` (6.12.87) and
`cifs-vuln-kernel` (6.12.92) for the pre-6.12.101/103 bugs; `security-kernel` already has
`CONFIG_IP_SCTP=y` + `CONFIG_INET_SCTP_DIAG=y` (DiagSpill).

**Verify the real Kconfig symbol (grep the Kconfig).** Several guessed symbols were wrong:
`CONFIG_IOAM6` does not exist in 6.12 (ioam6 core is built with IPv6; only
`CONFIG_IPV6_IOAM6_LWTUNNEL` gates the LWT path); the SCTP diag symbol is
`CONFIG_INET_SCTP_DIAG` (`def_tristate INET_DIAG`), not `CONFIG_SCTP_DIAG`; the ip6gre device is
`CONFIG_IPV6_GRE` (needs `CONFIG_NET_IPGRE_DEMUX`), not `CONFIG_IP6_GRE`. **Firecracker kernels
are module-less `vmlinux` — required options must be `=y`, not `=m`**; make the build verifier
reject `=m`. Always build a vuln + patched-control pair and a `kasan` variant.

**Struct-offset porting (`pahole` + `System.map`).** These PoCs carry per-kernel profile tables
(symbol offsets + struct field offsets) and abort with e.g. *"no exact fake-file profile"*. To
add a kernel: symbols from `grep -E ' (commit_creds|init_cred|work_for_cpu_fn)$' System.map`,
offset = address − `_text` (`0xffffffff81000000`); struct field offsets from a **same-config**
`CONFIG_DEBUG_INFO=y` build via `pahole -C file vmlinux` (`pahole`, `gdb`, `bpftool` are on the
test server). `struct file` is config-dependent and changed field order across versions — our
6.12.100 config is `f_count`=0, `f_lock`=8, `f_mode`=12, `f_op`=16, size 184. Deriving these is
routinely the difference between "unsupported" and a running exploit.

**PoC structure / adaptation.** They are single-file Python with embedded C helpers compressed
as base85+zlib blobs (`EMBEDDED_SOURCE_BLOBS`). Extract with
`zlib.decompress(base64.b85decode(blob))`, edit, re-embed with
`base64.b85encode(zlib.compress(src))` (see the PPPoEject profile patch in
`work_in_progress/CVE-2026-68121/poc/`). Prefer env overrides over editing embedded tables:
`*_ALLOW_ANY` / `DIRTYAH6_RECORD_FILE` (bypass the exact `uname` match; never match on the
build-specific `uname.version`), `*_NO_SHELL`, `*_ALLOW_ROOT` (container root),
`*_NETNS_ONLY` (direct-caps path, avoids the userns), and grooming knobs. Placement is
environment-sensitive: DirtyAH6's Ubuntu record lands in plain Docker but **not** on a
Kind/CNI node, where the Fedora-strategy record is needed — ship several records and try them
in order in the entrypoint.

**VM / run harness.** The base rootfs lacks `python3`/`gcc`/`openssl`/`sudo` (install them);
`security-rootfs` has python3/Docker/kind/kubectl but no gcc. `/dev/net/tun` and `/dev/fuse`
are mode `600` in the rootfs — `chmod 666` for unprivileged tests (real hosts ship 666). To
capture output from a PoC that wedges the guest, run it detached with stdout to `/dev/console`
(`setsid ... > /dev/console 2>&1 < /dev/null &`) and read it with `vmm console --full`; SSH dies
before the console does. `vmm --mount host:tag` created `/mnt/<tag>` but did **not** auto-mount
the host dir (verify with `findmnt` before relying on it). `vmm create/start` under sudo leave
the state json root-owned, so non-sudo `vmm list` shows nothing — use `sudo vmm list`/`sudo vmm
ssh`. Dirty-pagetable PoCs leave corrupted tables held by a detached `diagspill_hold`-style
process: recreate the VM per run and don't kill the holder. **PTE-present side channels
(prefetch/RDTSCP)**: dead on our **AMD Ryzen 7 5700U (Zen 2)** host while the translation is
TLB-cached — mapped and unmapped kernel addresses both time at ~36 cycles, so both the `h210`
KASLR locator and the `h209` vmalloc-carrier locator report 0 signal. Two workarounds:
(1) Firecracker boots an uncompressed `vmlinux` directly, so **virtual KASLR and
`RANDOMIZE_MEMORY` are inert** — `_text` was `0xffffffff81000000` across four reboots and the
vmalloc ring always lands near `0xffffc90000000000`; bypass locators with a fixed base env
override instead of rebuilding. (2) **Flush the TLB before every measurement** — a stride touch
of a 64 MiB buffer turns the signal back on (mapped ~90-1500 vs unmapped ~36-54 cycles); use a
*single* prefetch per flush (summing 32 hides the one informative first sample) and a narrow
scan range so the per-slot flush stays affordable. This is the fix that made the PPPoEject
carrier work.

**`skbuff_small_head` cross-cache:** small skb heads (head size <= `SKB_SMALL_HEAD_CACHE_SIZE`)
come from the dedicated `skbuff_small_head` `kmem_cache` (640-byte objects), *not* `kmalloc-N`.
Reclaiming one with a `struct fdtable` therefore needs a cross-cache page reuse (drain the slab
page to the buddy allocator, then let the fdtable allocation re-use it) — the per-target groom
in the manizada PoCs (`h316`/`h321`/`h322`/`h318`). Larger heads fall through to generic
`kmalloc`, but for PPPoEject the payload/geometry derives from the ring address' high bytes, so
reaching kmalloc needs the ring ~64 GiB up the vmalloc area (AB >= 0x10 in `0xffffc9ab...`),
which the allocator does not do in practice.

**Naming:** do not name a PoC directory `exploit/` — the root `.gitignore` pattern `exploit`
matches *directories* too and silently excludes it from git. Use `poc/` (as DirtyAH6 does).

Status at end of the PPPoEject session: **DirtyAH6 complete** (LPE + Docker + KinD breakout on
6.12.107); **TUNderflow closed for 6.12** (netkit headroom UAPI is 6.14+); **DiagSpill** paused.
**PPPoEject (CVE-2026-68121)** ported to 6.12.100 far enough to run the full race: the `h210`
KASLR locator is bypassed (KASLR inert on Firecracker) and the `h209` vmalloc carrier locator is
fixed with the TLB-flush technique above, so the carrier is found in cycle 1. The stale PPPoE
head write is **KASAN-confirmed** on 6.12.100 (`pppoe_sendmsg+0x51c`, freed object in
`skbuff_small_head`). Still **not LPE**: the low-order path needs the 6.12 cross-cache groom
re-derived (objects-per-slab / `cpu_partial` / slab-page free timing differ from 6.8). Paused in
`work_in_progress/CVE-2026-68121/`; the README carries current status and a
"Where to pick up next".

**PPPoEject session 2 (6.12 grooming):** the carrier locator was made cheap and reliable
(32 MiB TLB flush + 5 passes + 512-slot scan; 1-4 lifecycle cycles, validated against
`/proc/vmallocinfo`). The victim is a dedicated 640-byte `skbuff_small_head` object (order 2,
25 objects), so upstream's 3000-byte-payload `h316` groom never touched it — retargeted to
payload 201. And only fd 2 can be the trigger, so `h318` no longer rotates lanes away from it.
This SLUB config's kmalloc caches stop at 8 KiB, so the 4096-entry fd array is a raw order-3
page allocation. Long campaigns were running on `pppoeject-exp`/`pppoeject-exp8` at the end of
the session; see README section 1b for the exact changes and the remaining ordering blocker.

## Linux Kernel CVE Triage (`linux_cve_triage/`)

Use the **`linux-cve-triage`** skill (installed at `~/.claude/skills/linux-cve-triage/`) when triaging kernel CVEs for LPE or container breakout viability. The skill provides a 15-point scoring rubric, exploitation blocker checklist (kfree_rcu, fdget, refcounting), spray primitive reference by slab cache size, and default container seccomp profiles. Invoke it for batch triage or deep single-CVE analysis.

Triage criteria and log are in `linux_cve_triage/CRITERIA.md` and `linux_cve_triage/triage_log.md`. The `linux-vulns` git repo is cloned to `linux_cve_triage/linux-vulns/` (CVE data in `cve/published/YYYY/`).

## CVE Categories

- **Unpatchable Kubernetes vulns**: CVE-2020-8554, CVE-2020-8562, CVE-2021-25740 — design-level issues that can't be fixed without breaking changes
- **SSRF via API server**: CVE-2020-8561 (webhook-based), kinvolk-proxy-exploit (pod annotation-based)
- **Container escape / host file access**: CVE-2021-30465 (runc symlink race), CVE-2022-23648 (containerd volume mount), CVE-2025-31133 (runc maskedPaths race)
- **Page-cache corruption (container breakout)**: CVE-2026-46331 (PeditCow — tc pedit), fragnesia (ESP-in-TCP), CVE-2026-43503 (DirtyClone — XFRM/TEE), CVE-2026-31431 (CopyFail — AF_ALG)
- **In-slab overflow / Dirty-Pagetable (container breakout)**: CVE-2026-53362 (IPv6 fraggap overflow into skb_shared_info → nr_frags → pipe page UAF → Dirty-Pagetable → core_pattern root shell; Ubuntu vmm 4-level port of the RHEL 10 PoC, 6.12.87 `ip6frag-kernel`)
- **Kernel UAF / LPE**: CVE-2026-23111 (nftables UAF → modprobe_path overwrite via ret2dir)
- **Kernel logic / credential disclosure**: CVE-2026-46333 (ptrace `__ptrace_may_access()` `mm==NULL` bypass → `pidfd_getfd()` steals fds from dying setuid/setgid processes)

## Adding New PoCs

Follow the existing pattern: create a `CVE-YYYY-NNNNN/` directory with a `README.md` documenting prerequisites, setup steps, and expected output. Include all necessary manifests and scripts. Update the root `README.md` with a one-line description.

For kernel exploit PoCs, always develop in a Firecracker VM on the test server — never on the host. For container breakout adaptations from LPE exploits, follow the standardised file structure and two-attack-path pattern documented above.

## PoC Documentation (`pocdocs/`)

HTML explainer documents live in `pocdocs/`, one per PoC variant. See `pocdocs/cve-2021-25740-loadbalancer.html` as the reference example.

### Style and structure

- **Self-contained HTML** — no external dependencies (CSS, JS, fonts, images). Everything is inline.
- **Dark technical theme** — background `#0d1117`, text `#c9d1d9`, monospace accents. Colour palette defined as CSS custom properties in `:root`.
- **Sections**: Header (CVE badge, severity, links) -> Background -> Diagrams -> Attack explanation -> Reproduction steps (terminal-style code blocks) -> Mitigation.

### Animated SVG diagrams

Diagrams are inline `<svg>` elements with SMIL `<animate>` tags (no JavaScript).

- **Colour conventions**: green (`#3fb950`) for legitimate traffic, red (`#f85149`) for malicious/redirected traffic, blue (`#1f6feb`) for attacker namespace, red (`#da3633`) for victim namespace, orange (`#d29922`) for services/MetalLB, purple (`#bc8cff`) for EndpointSlices.
- **Traffic flow animations**: Use `<circle>` elements as packets moving along each hop. Each packet gets its own `<animate>` for `cx`, `cy`, and `opacity`.
- **Looping**: Use `repeatCount="indefinite"` with the full cycle duration (e.g. `dur="3.6s"`). The actual movement occupies a small fraction of the cycle via `keyTimes`, with the rest as invisible idle time. Stagger packets across hops using `begin` offsets (e.g. `0s`, `0.5s`, `1s`).
- **Pulsing elements**: Use `<animate attributeName="stroke-opacity" values="0.5;1;0.5" dur="2s" repeatCount="indefinite"/>` to draw attention to key objects like modified EndpointSlices.
- **Arrow markers**: Defined in a `<defs>` block, one per colour (e.g. `#arrowGreen`, `#arrowRed`). Reused across all SVGs via `marker-end="url(#arrowGreen)"`.
- **Layout**: Each diagram should show the full traffic path including all intermediaries (MetalLB, kube-proxy/node, etc.) — don't skip hops even if simplifying.
