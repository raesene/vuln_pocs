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

## Common Tools and Patterns

- **KinD (Kubernetes in Docker)** is the primary local cluster tool: `kind create cluster --config kind-config.yaml`
- **kubectl** is used for all cluster interaction — applying manifests, exec'ing into pods, checking logs
- **kubectl proxy** is frequently used to expose the API server locally for curl-based exploits
- Several PoCs exploit TOCTOU (time-of-check/time-of-use) race conditions and may require multiple attempts
- **Compiled C race helpers** are needed for tight TOCTOU windows (e.g., CVE-2025-31133). Bash loops are too slow for sub-millisecond races — use pthreads with `sched_yield()` and `usleep()` instead
- For runc-level PoCs, the OCI config must **not** mount `/dev` as tmpfs — otherwise runc uses the tmpfs `/dev/null` (which the race can't reach from outside the mount namespace). Docker always adds `/dev` tmpfs, making Docker-based runc race exploits significantly harder
- For runc race PoCs, the container's own process args should perform the exploit action (e.g., `"args": ["sh", "-c", "echo PAYLOAD > /proc/sys/kernel/core_pattern"]`), not `runc exec` after the fact — the race window is during `runc run`/`runc create`, and masking is already applied by the time `exec` runs

### Kernel heap exploit techniques (CVE-2026-23111)

- **Slab defragmentation** before freeing the victim object: spray filler objects to exhaust free slots in the target slab cache, so the freed victim slot is the first available for reclamation. Without this, sprays compete with many existing free slots and reclamation is unreliable
- **Table userdata** (`NFTA_TABLE_USERDATA`) is the best nftables heap spray primitive for `kmalloc-cg-128` — full content control from byte 0, correct GFP flags (`GFP_KERNEL_ACCOUNT`). `msgsnd` goes to a separate bucket slab; `setxattr` has a 40-byte header; `add_key` uses non-accounted GFP flags
- **ret2dir (physmap)**: `mmap` a page, read `/proc/self/pagemap` for the physical address, compute `page_offset_base + phys_addr` for the kernel direct-map alias. Gives a user-controlled page at a kernel virtual address — bypasses SMAP without needing a stack pivot or ROP chain. Requires readable pagemap (default in VMs, restricted in containers)
- **`modprobe_path` overwrite**: After gaining arbitrary write (via ret2dir + a memcpy gadget), overwrite the kernel's `modprobe_path` string, then execute a file with unknown magic bytes — the kernel runs the attacker's script as root via `call_usermodehelper`
- **Gadget selection for nftables UAF**: The `nft_expr_ops.eval` function pointer is called with `(expr, regs, pkt)` where `expr` points to attacker-controlled data. Functions that read parameters from their first argument (like `crypto_akcipher_sync_post` which does `memcpy(dst, src, len)` from struct fields) make effective "call-oriented" gadgets without needing ROP
- **SMAP and ZERO_SIZE_PTR**: `ZERO_SIZE_PTR` (address 16) is a userspace address — SMAP blocks kernel code from dereferencing it. Use physmap (kernel direct-map) addresses instead when the kernel needs to read/write through attacker-supplied pointers
- **Firecracker VM testing**: Use `vmm console <vm> --follow=false --full` to capture serial console output including kernel panics. Set `panic=0` + `panic_on_oops=1` at runtime so the VM halts on crash without rebooting

## Linux Kernel CVE Triage (`linux_cve_triage/`)

Use the **`linux-cve-triage`** skill (installed at `~/.claude/skills/linux-cve-triage/`) when triaging kernel CVEs for LPE or container breakout viability. The skill provides a 15-point scoring rubric, exploitation blocker checklist (kfree_rcu, fdget, refcounting), spray primitive reference by slab cache size, and default container seccomp profiles. Invoke it for batch triage or deep single-CVE analysis.

## CVE Categories

- **Unpatchable Kubernetes vulns**: CVE-2020-8554, CVE-2020-8562, CVE-2021-25740 — design-level issues that can't be fixed without breaking changes
- **SSRF via API server**: CVE-2020-8561 (webhook-based), kinvolk-proxy-exploit (pod annotation-based)
- **Container escape / host file access**: CVE-2021-30465 (runc symlink race), CVE-2022-23648 (containerd volume mount), CVE-2025-31133 (runc maskedPaths race)
- **Kernel UAF / LPE**: CVE-2026-23111 (nftables UAF → modprobe_path overwrite via ret2dir)

## Adding New PoCs

Follow the existing pattern: create a `CVE-YYYY-NNNNN/` directory with a `README.md` documenting prerequisites, setup steps, and expected output. Include all necessary manifests and scripts. Update the root `README.md` with a one-line description.

## PoC Documentation (`pocdocs/`)

HTML explainer documents live in `pocdocs/`, one per PoC variant. See `pocdocs/cve-2021-25740-loadbalancer.html` as the reference example.

### Style and structure

- **Self-contained HTML** — no external dependencies (CSS, JS, fonts, images). Everything is inline.
- **Dark technical theme** — background `#0d1117`, text `#c9d1d9`, monospace accents. Colour palette defined as CSS custom properties in `:root`.
- **Sections**: Header (CVE badge, severity, links) → Background → Diagrams → Attack explanation → Reproduction steps (terminal-style code blocks) → Mitigation.

### Animated SVG diagrams

Diagrams are inline `<svg>` elements with SMIL `<animate>` tags (no JavaScript).

- **Colour conventions**: green (`#3fb950`) for legitimate traffic, red (`#f85149`) for malicious/redirected traffic, blue (`#1f6feb`) for attacker namespace, red (`#da3633`) for victim namespace, orange (`#d29922`) for services/MetalLB, purple (`#bc8cff`) for EndpointSlices.
- **Traffic flow animations**: Use `<circle>` elements as packets moving along each hop. Each packet gets its own `<animate>` for `cx`, `cy`, and `opacity`.
- **Looping**: Use `repeatCount="indefinite"` with the full cycle duration (e.g. `dur="3.6s"`). The actual movement occupies a small fraction of the cycle via `keyTimes`, with the rest as invisible idle time. Stagger packets across hops using `begin` offsets (e.g. `0s`, `0.5s`, `1s`).
- **Pulsing elements**: Use `<animate attributeName="stroke-opacity" values="0.5;1;0.5" dur="2s" repeatCount="indefinite"/>` to draw attention to key objects like modified EndpointSlices.
- **Arrow markers**: Defined in a `<defs>` block, one per colour (e.g. `#arrowGreen`, `#arrowRed`). Reused across all SVGs via `marker-end="url(#arrowGreen)"`.
- **Layout**: Each diagram should show the full traffic path including all intermediaries (MetalLB, kube-proxy/node, etc.) — don't skip hops even if simplifying.
