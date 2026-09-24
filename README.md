# Kubernetes & Container Security PoCs

A collection of proof-of-concept exploits for Kubernetes, container-runtime and Linux
kernel vulnerabilities, used for demos and educational purposes.

> **Educational use only.** These PoCs are provided to help security practitioners
> understand and validate vulnerabilities. Do not use them against systems you do not
> own or have explicit permission to test. Many of them are destructive or unstable
> and should only be run in disposable, isolated environments (the kernel exploits in
> particular should be run in throwaway VMs).

## PoCs

* **CVE-2020-8554** — MITM via Services with arbitrary `externalIPs`/LoadBalancer IPs: a user who can create Services can hijack traffic destined for other addresses.
* **CVE-2020-8561** — API server SSRF: `kube-apiserver` can be induced to follow a webhook URL to a localhost/`169.254.169.254` address.
* **CVE-2020-8562** — API server proxy allows access to services bound to the node's localhost interface (timing-dependent, unpatchable).
* **CVE-2021-25740** — cross-namespace exposure via `Endpoint`/`EndpointSlice` manipulation, with LoadBalancer and Ingress variants.
* **CVE-2021-30465** — runc symlink race container escape via a crafted volume configuration.
* **CVE-2022-23648** — containerd CRI plugin volume mount allows reading host files.
* **CVE-2025-31133** — runc `maskedPaths` TOCTOU race container escape (writes `/proc/sys/kernel/core_pattern`).
* **CVE-2026-2270** — `kube-controller-manager` StatefulSet/ControllerRevision confused deputy: namespace-scoped write access yields a pod in another namespace (Secret + ServiceAccount token exfiltration).
* **CVE-2026-23111** — nftables use-after-free local privilege escalation; root via `modprobe_path` overwrite using ret2dir (physmap).
* **CVE-2026-31431** — CopyFail: page-cache corruption through read-only bind mounts / shared image layers, with Docker, Podman, runc and Kubernetes container-escape variants.
* **CVE-2026-43499** — GhostLock: rtmutex use-after-free local privilege escalation and container breakout (DirtyMode via `inet6_protos` hijack).
* **CVE-2026-43503** — DirtyClone: XFRM TEE clone launders `SKBFL_SHARED_FRAG`, giving an in-place ESP decrypt over page cache (LPE + container escape).
* **CVE-2026-46243** — CIFSwitch: CIFS/keyrings LPE; container breakout via root-run `cifs.upcall` loading attacker-controlled NSS libraries.
* **CVE-2026-46331** — PeditCow: `tc` pedit range-validation bug gives a deterministic page-cache write and container breakout.
* **CVE-2026-46333** — `__ptrace_may_access()` logic bug: credential disclosure (host `/etc/shadow`, SSH host keys) and container breakout via `pidfd_getfd()`.
* **CVE-2026-53362** — IPv6 `fraggap` overflow into `skb_shared_info` → pipe page UAF → Dirty-Pagetable → `core_pattern` root shell.
* **CVE-2026-64531** — OVSwrap: Open vSwitch action-parser 16-bit integer wraparound enables unprivileged container breakout.
* **CVE-2026-80844** — DirtyAH6: IPv6 IPsec AH out-of-bounds read/write local privilege escalation.
* **CVE-2026-81000** — TUNderflow: TUN/TAP receive-headroom underflow reached via the Open vSwitch datapath (LPE).
* **fragnesia** — ESP-in-TCP page-cache corruption container breakout (deterministic byte flips in spliced pages).
* **kinvolk-proxy-exploit** — API server proxy SSRF by patching pod objects (no CVE; working as intended but violates a security expectation).

## Other directories

* `pocdocs/` — self-contained HTML explainer documents, one per PoC variant.
* `linux_cve_triage/` — Linux kernel CVE triage rubric, criteria and triage log.
* `work_in_progress/` — PoCs still under development.
