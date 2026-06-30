# Linux Kernel CVE Triage Log

Triaged from `linux-vulns` repo, reverse chronological order.
Criteria: see `CRITERIA.md`.

## Batch 1: CVE-2026-52907 through CVE-2026-46236

| CVE | Subsystem | Title | Must-Have | Score | Verdict |
|---|---|---|---|---|---|
| CVE-2026-52907 | media/rockchip | rkcif: fix off by one bugs | FAIL: not server subsystem | - | Skip |
| CVE-2026-52906 | fs/9p | 9p: fix access mode flags | PASS | 3 | Skip (logic bug, not mem corruption) |
| CVE-2026-52905 | mm/damon | disallow non-power of two min_region_sz | FAIL: not exploitable (param validation) | - | Skip |
| CVE-2026-52904 | drm/nouveau | fix nvkm_device leak | FAIL: GPU driver | - | Skip |
| CVE-2026-46333 | kernel/ptrace | slightly saner 'get_dumpable()' logic | PASS | 5 | Low — access control logic fix, not mem corruption |
| CVE-2026-46332 | greybus | gb-beagleplay: bound bootloader receive buffering | FAIL: not server subsystem | - | Skip |
| CVE-2026-46330 | net/smc | Revert "net/smc: Introduce TCP ULP support" | PASS | 4 | Low — revert, unclear vuln mechanics |
| CVE-2026-46329 | fs/erofs | handle end of filesystem properly | FAIL: erofs niche | - | Skip |
| CVE-2026-46328 | security/apparmor | fix rlimit for posix cpu timers | PASS | 3 | Skip — rlimit enforcement bug, no mem corruption |
| CVE-2026-46327 | drivers/md | dm: fix unlocked test for dm_suspended_md | PASS | 3 | Skip — race but root-only (dm requires CAP_SYS_ADMIN) |
| CVE-2026-46326 | iio/pressure | mprls0025pa: fix spi_transfer struct init | FAIL: sensor driver | - | Skip |
| CVE-2026-46325 | RDMA/rxe | Fix iova-to-va conversion for MR page sizes | FAIL: RDMA, niche HW | - | Skip |
| CVE-2026-46324 | netfilter/nf_tables | use list_del_rcu for netlink hooks | PASS | 7 | Low — RCU list traversal issue, needs CAP_NET_ADMIN, hard to weaponise |
| CVE-2026-46323 | net/core/gro | don't merge zcopy skbs | PASS | 5 | Low — data corruption path but hard to control |
| CVE-2026-46322 | drivers/net/tun | free page on build_skb failure in tun_xdp_one() | PASS | 4 | Skip — memory leak on error, not corruption |
| CVE-2026-46321 | drivers/net/tun | free page on short-frame rejection | PASS | 4 | Skip — same as above |
| CVE-2026-46320 | drivers/net/tap | free page on error paths | PASS | 4 | Skip — memory leak |
| CVE-2026-46319 | net/sched/act_ct | Only release RCU read lock after ct_ft | PASS | 5 | Low — RCU usage bug, needs TC + conntrack config |
| CVE-2026-46318 | mm/hugetlb | Revert hugetlbfs mmap_prepare | PASS | 4 | Skip — regression revert |
| CVE-2026-46317 | KVM/arm64 | Reassign nested_mmus array behind mmu_lock | FAIL: arm64-only | - | Skip |
| CVE-2026-46316 | KVM/arm64 | vgic-its: Drop translation cache ref | FAIL: arm64-only | - | Skip |
| CVE-2026-46315 | io_uring/waitid | clear waitid info before copying to userspace | PASS | 9 | **Medium** — info leak from io_uring, unprivileged, useful for KASLR bypass chain |
| CVE-2026-46314 | drm/v3d | Reject empty multisync extension | FAIL: GPU driver | - | Skip |
| CVE-2026-46313 | media/intel/ipu6 | fix error pointer dereference | FAIL: not server subsystem | - | Skip |
| CVE-2026-46312 | media/videobuf2 | Set vma_flags in vb2_dma_sg_mmap | FAIL: not server subsystem | - | Skip |
| CVE-2026-46311 | drm/amdgpu | fix access to stale wptr mapping | FAIL: GPU driver | - | Skip |
| CVE-2026-46310 | media/renesas | NULL pointer deref on module unload | FAIL: not server subsystem | - | Skip |
| CVE-2026-46309 | drm/xe | Reject coh_none PAT index | FAIL: GPU driver | - | Skip |
| CVE-2026-46308 | pmdomain/mediatek | fix use-after-free in scpsys | FAIL: not server subsystem (SoC) | - | Skip |
| CVE-2026-46307 | wifi/ath5k | do not access array OOB | FAIL: Wi-Fi driver | - | Skip |
| CVE-2026-46306 | net/core | flow_dissector: do not dissect PPPoE PFC frames | PASS | 4 | Skip — bounds check, not practically exploitable |
| CVE-2026-46305 | staging/rtl8723bs | avoid NULL pointer deref | FAIL: staging Wi-Fi driver | - | Skip |
| CVE-2026-46304 | nvme/target | avoid recursive workqueue flush | FAIL: NVMe target (niche server role) | - | Skip |
| CVE-2026-46303 | fs/isofs | validate Rock Ridge CE extent | PASS | 5 | Low — needs mounting a crafted ISO, not typical attack surface |
| CVE-2026-46302 | security/selinux | allow multiple opens of policy | PASS | 2 | Skip — logic fix |
| CVE-2026-46301 | spi/topcliff-pch | UAF on unbind | FAIL: niche SPI driver | - | Skip |
| CVE-2026-46300 | net/core/skbuff | preserve shared-frag marker during coalescing | PASS | 6 | Low — page cache corruption via ESP, needs IPsec |
| CVE-2026-46299 | fs/hfsplus | held lock freed on fill_super | PASS | 4 | Low — needs mounting crafted HFS+ |
| CVE-2026-46298 | arch/powerpc | papr-hvpipe: Fix race with interrupt handler | FAIL: PowerPC-only | - | Skip |
| CVE-2026-46297 | net/ethernet/wangxun | use request_irq for VF misc interrupt | FAIL: niche NIC driver | - | Skip |
| CVE-2026-46296 | spi/s3c64xx | fix NULL-deref on driver unbind | FAIL: ARM SoC SPI | - | Skip |
| CVE-2026-46295 | KVM/x86 | Do IRR scan in __kvm_apic_update_irr | PASS | 3 | Skip — KVM host-side, not guest escape |
| CVE-2026-46294 | drivers/md/dm | fix buffer overflow in ioctl processing | PASS | 2 | Skip — root-only, no security impact per author |
| CVE-2026-46293 | clk/microchip | mpfs-ccc: fix OOB during output registration | FAIL: not server subsystem | - | Skip |
| CVE-2026-46292 | pmdomain/core | Fix detach for virtual devices in genpd | FAIL: power domain, SoC | - | Skip |
| CVE-2026-46291 | crypto/caam | guard HMAC key hex dumps | FAIL: NXP crypto accelerator | - | Skip |
| CVE-2026-46290 | x86/efi | Fix graceful fault handling after FPU changes | PASS | 2 | Skip — EFI runtime, not reachable from userspace |
| CVE-2026-46289 | lib/scatterlist | fix length calculations in extract_kvec_to_sg | PASS | 5 | Low — core lib but unclear userspace trigger path |
| CVE-2026-46288 | drivers/of | unittest: fix UAF in of_unittest_changeset | FAIL: devicetree unittest, not production code | - | Skip |
| CVE-2026-46287 | net/ethernet/wangxun | txgbe: fix RTNL assertion | FAIL: niche NIC driver | - | Skip |
| CVE-2026-46286 | leds/qcom-lpg | Check for array overflow | FAIL: LED driver | - | Skip |
| CVE-2026-46285 | mtd/docg3 | fix UAF in docg3_release() | FAIL: MTD flash driver | - | Skip |
| CVE-2026-46284 | mm/hugetlb | fix early boot crash on parameters | PASS | 1 | Skip — boot-time only |
| CVE-2026-46283 | drivers/char/tpm | Use kfree_sensitive() for auth session | PASS | 2 | Skip — info leak of TPM key material, needs TPM access |
| CVE-2026-46282 | iio/frequency | admv1013: fix NULL pointer deref | FAIL: IIO sensor | - | Skip |
| CVE-2026-46281 | mm/vmalloc | fix buffer overflow in vrealloc_node_align() | PASS | 6 | Low — heap overflow but internal API, unclear userspace trigger, only 6.18+ |
| CVE-2026-46280 | lib/test_hmm | evict device pages on close to avoid UAF | FAIL: test module, not production | - | Skip |
| CVE-2026-46279 | mm/alloc_tag | clear codetag for pre-init pages | PASS | 2 | Skip — boot-time race |
| CVE-2026-46278 | drm/imagination | Fix segfault in ftrace mask | FAIL: GPU driver | - | Skip |
| CVE-2026-46277 | mm/zone_device | do not touch device folio after folio_free() | PASS | 4 | Low — UAF but only for zone_device (DAX/PMEM/GPU) |
| CVE-2026-46276 | drm/amdgpu | fix zero-size GDS range init on RDNA4 | FAIL: GPU driver | - | Skip |
| CVE-2026-46275 | bluetooth/hci_uart | fix UAFs and race conditions in close/init | FAIL: Bluetooth | - | Skip |
| CVE-2026-46274 | io_uring/io-wq | check predecessor is hashed in remove_pending | PASS | 5 | Low — io_uring internal, unclear impact |
| CVE-2026-46273 | net/ethernet/ibm | ibmveth: Disable GSO for small MSS | FAIL: IBM pSeries-only | - | Skip |
| CVE-2026-46272 | hwtracing/coresight | tmc-etr: Fix race sysfs vs perf | FAIL: ARM CoreSight | - | Skip |
| CVE-2026-46271 | wifi/ath12k | do WoW offloads only on primary link | FAIL: Wi-Fi | - | Skip |
| CVE-2026-46270 | power/supply | rt9455: Fix UAF in power_supply_changed | FAIL: charger driver | - | Skip |
| CVE-2026-46269 | pinctrl/canaan | k230: Fix NULL deref parsing devicetree | FAIL: SoC pinctrl | - | Skip |
| CVE-2026-46268 | PCI/P2PDMA | Fix p2pmem_alloc_mmap() warning | PASS | 2 | Skip — warning fix, no corruption |
| CVE-2026-46267 | net/nfc/hci | shdlc: Stop timers before freeing | FAIL: NFC | - | Skip |
| CVE-2026-46266 | net/ipv4+ipv6 | RAW sockets: IPPROTO_RAW must drop incoming ICMP | PASS | 3 | Skip — logic fix for ICMP handling |
| CVE-2026-46265 | RDMA/hns | Fix WQ_MEM_RECLAIM warning | FAIL: RDMA HW driver | - | Skip |
| CVE-2026-46264 | drm/xe | pf: Fix sysfs initialization | FAIL: GPU driver | - | Skip |
| CVE-2026-46263 | drm/amd/display | Fix OOB stream encoder index | FAIL: GPU driver | - | Skip |
| CVE-2026-46262 | sound/soc | fsl_xcvr: Revert fix missing lock | FAIL: sound | - | Skip |
| CVE-2026-46261 | spi/wpcm-fiu | Fix potential NULL pointer deref | FAIL: SoC SPI | - | Skip |
| CVE-2026-46260 | net/ipv6 | Fix OOB access in fib6_add_rt2node() | PASS | 6 | Low — OOB read (not write) in IPv6 FIB, regression in narrow version range |
| CVE-2026-46259 | fs/proc | fix missing RCU protection reading real_parent | PASS | 4 | Skip — stale pointer read, likely just info leak or crash |
| CVE-2026-46258 | gpio/cdev | Avoid NULL deref in linehandle_create | FAIL: GPIO chardev | - | Skip |
| CVE-2026-46257 | clocksource/sp804 | Fix Oops when not registered as sched_clock | FAIL: ARM timer driver | - | Skip |
| CVE-2026-46256 | NFS/localio | prevent direct reclaim recursion | PASS | 2 | Skip — deadlock prevention, not corruption |
| CVE-2026-46255 | dmaengine/fsl-edma | don't explicitly disable clocks in .remove | FAIL: DMA engine | - | Skip |
| CVE-2026-46254 | security/apparmor | Allow unaligned DFA tables | PASS | 2 | Skip — parser fix |
| CVE-2026-46253 | fs/pstore/ram | fix buffer overflow in persistent_ram_save_old | PASS | 4 | Low — pstore is early-boot/crash context, not user-reachable |
| CVE-2026-46252 | drivers/regulator | fix locking in regulator_resolve_supply | FAIL: regulator framework (embedded) | - | Skip |
| CVE-2026-46251 | fs/btrfs | fix block_group_tree dirty_list corruption | PASS | 4 | Low — btrfs internal corruption, needs mount + specific operations |
| CVE-2026-46250 | arch/mips | Work around LLVM bug | FAIL: MIPS-only | - | Skip |
| CVE-2026-46249 | net/ethernet/marvell | Fix PF driver crash with kexec | FAIL: niche NIC | - | Skip |
| CVE-2026-46248 | wifi/ath12k | clear stale link mapping | FAIL: Wi-Fi | - | Skip |
| CVE-2026-46247 | clk/qcom | gfx3d: add parent to parent request map | FAIL: Qualcomm SoC | - | Skip |
| CVE-2026-46246 | power/supply | pm8916_lbc: Fix UAF for extcon in IRQ | FAIL: charger driver | - | Skip |
| CVE-2026-46245 | drm/amd/display | Fix dc_link NULL handling | FAIL: GPU driver | - | Skip |
| CVE-2026-46244 | netfilter/nft_inner | Fix IPv6 inner_thoff desync | PASS | 5 | Low — nftables inner header parsing, needs CAP_NET_ADMIN for rules |
| CVE-2026-46243 | fs/smb/client | reject userspace cifs.spnego descriptions | PASS | 3 | Skip — SMB client, needs mount |
| **CVE-2026-46242** | **fs/eventpoll** | **fix ep_remove struct eventpoll / struct file UAF** | **PASS** | **13** | **HIGH — full write-up** |
| CVE-2026-46241 | spi/mpc52xx | fix UAF on registration failure | FAIL: niche SPI driver | - | Skip |
| CVE-2026-46240 | media/qcom/iris | Fix UAF in iris_release_internal_buffers | FAIL: media SoC driver | - | Skip |
| CVE-2026-46239 | media/ov5647 | Fix runtime PM refcount leak | FAIL: camera sensor | - | Skip |
| CVE-2026-46238 | net/batman-adv | stop caching unowned originator pointers | PASS | 4 | Skip — batman-adv mesh networking, niche |
| CVE-2026-46236 | media/rc | xbox_remote: heed DMA restrictions | FAIL: Xbox remote, not server | - | Skip |

## Batch 2: CVE-2026-52907 through CVE-2026-46267

| CVE | Subsystem | Title | Must-Have | Score | Verdict |
|---|---|---|---|---|---|
| CVE-2026-52907 | media/rockchip/rkcif | OOB array access in Rockchip camera driver | FAIL: ARM SoC only | - | Skip |
| CVE-2026-52906 | 9p (fs/9p) | Access mode flags ORed instead of replaced → INVALID_UID | FAIL: 9p not default | - | Skip |
| CVE-2026-52905 | mm/damon/core | Non-power-of-2 min_region_sz via damon_start() | FAIL: niche subsystem, logic bug | - | Skip |
| CVE-2026-52904 | drm/nouveau | nvkm_device + PCI ref leak on aperture removal failure | FAIL: GPU driver | - | Skip |
| CVE-2026-46333 | ptrace | Dumpable check bypass for mm-less tasks, cap-dropped root can ptrace kthreads | PASS | 4 | Low — Qualys-reported, info leak only, no escalation beyond capability bypass |
| CVE-2026-46332 | greybus/gb-beagleplay | Buffer overflow in BeagleBone bootloader rx | FAIL: ARM-only | - | Skip |
| CVE-2026-46330 | net/smc (TCP ULP) | UAF via VFS invariant violation converting TCP→SMC | PASS | 7 | Low — UAF real but SMC module not default, 6.19+ only |
| CVE-2026-46329 | erofs | I/O beyond filesystem end not zeroed for file-backed mounts | FAIL: erofs not default | - | Skip |
| CVE-2026-46328 | apparmor | RLIMIT_CPU not enforced during profile transition | PASS | 2 | Skip — policy enforcement bug, no corruption |
| CVE-2026-46327 | dm (dm-zone) | Race in dm_suspended_md check missing lock | FAIL: dm-zone niche | - | Skip |
| CVE-2026-46326 | iio/pressure | Uninitialized spi_transfer in mprls0025pa | FAIL: IIO sensor driver | - | Skip |
| CVE-2026-46325 | RDMA/rxe | Incorrect iova-to-va for non-PAGE_SIZE MR pages | FAIL: RDMA soft emu | - | Skip |
| CVE-2026-46324 | netfilter/nf_tables | list_del (not list_del_rcu) on concurrent hook walk | PASS | 7 | Low — list corruption race, needs CAP_NET_ADMIN, hard to weaponize |
| CVE-2026-46323 | net: gro | Zcopy skbs merged without refcount fixup → UAF on frags | PASS | **9** | **Medium — deterministic UAF on page frags, container-reachable via veth+zcopy** |
| CVE-2026-46322 | tun | Page leak on build_skb failure in tun_xdp_one | FAIL: DoS-only (mem leak) | - | Skip |
| CVE-2026-46321 | tun | Page leak on short-frame rejection in tun_xdp_one | FAIL: DoS-only (mem leak) | - | Skip |
| CVE-2026-46320 | tap | Page leak on error paths in tap_get_user_xdp | FAIL: DoS-only (mem leak) | - | Skip |
| CVE-2026-46319 | net/sched: act_ct | RCU UAF race in flow table lookup → LPE | PASS | **9** | **Medium — ZDI-confirmed LPE, needs CAP_NET_ADMIN, tight race** |
| CVE-2026-46318 | mm/hugetlbfs | mmap_prepare VMA lock leak (6.19+ only) | FAIL: 6.19+ only, mem leak | - | Skip |
| CVE-2026-46317 | KVM: arm64 nested | nested_mmus array UAF during realloc race | FAIL: ARM64-only | - | Skip |
| CVE-2026-46316 | KVM: arm64 vgic-its | Translation cache double-put UAF | FAIL: ARM64-only | - | Skip |
| CVE-2026-46315 | io_uring/waitid | Uninit info struct leaked to userspace | PASS | 7 | Low — fully unpriv KASLR bypass via io_uring, but info leak only |
| CVE-2026-46314 | drm/v3d | Infinite loop via self-referential multisync extension | FAIL: ARM/Broadcom | - | Skip |
| CVE-2026-46313 | media/intel/ipu6 | ERR_PTR deref in probe error path | FAIL: camera driver | - | Skip |
| CVE-2026-46312 | media/videobuf2 | Missing VM_DONTEXPAND/VM_DONTDUMP in dma-sg mmap | FAIL: media/v4l2 | - | Skip |
| CVE-2026-46311 | drm/amdgpu/userq | Stale wptr mapping after unmap | FAIL: GPU driver | - | Skip |
| CVE-2026-46310 | media/renesas vsp1 | NULL deref on module unload | FAIL: ARM/Renesas | - | Skip |
| CVE-2026-46309 | drm/xe | coh_none PAT index leaks stale DRAM data | FAIL: Intel Xe GPU | - | Skip |
| CVE-2026-46308 | pmdomain/mediatek | UAF in scpsys bus protection error path | FAIL: ARM/MediaTek | - | Skip |
| CVE-2026-46307 | wifi/ath5k | OOB array write in tx tasklet | FAIL: wifi driver | - | Skip |
| CVE-2026-46306 | flow_dissector | PPPoE PFC frames unaligned access | FAIL: MIPS-only | - | Skip |
| CVE-2026-46305 | staging/rtl8723bs | NULL deref in rtw_cbuf_alloc | FAIL: staging driver | - | Skip |
| CVE-2026-46304 | nvmet | Recursive workqueue flush deadlock in ctrl free | FAIL: nvmet target | - | Skip |
| CVE-2026-46303 | isofs | Rock Ridge CE extent not validated | FAIL: DoS-only, needs mount | - | Skip |
| CVE-2026-46302 | selinux | Single-open lock blocks /sys/fs/selinux/policy reads | FAIL: DoS-only | - | Skip |
| CVE-2026-46301 | spi/topcliff-pch | UAF on unbind of Intel Topcliff PCH SPI | FAIL: embedded SPI | - | Skip |
| CVE-2026-46300 | net: skbuff | Shared-frag marker lost → ESP decrypts over page-cache frags | PASS | 6 | Low — page-cache corruption but needs IPsec, uncontrolled content |
| CVE-2026-46299 | hfsplus | Held lock freed on fill_super error | FAIL: lock warning on mount | - | Skip |
| CVE-2026-46298 | pseries/papr-hvpipe | Deadlock with interrupt handler | FAIL: IBM pSeries | - | Skip |
| CVE-2026-46297 | net/libwx | IRQF_ONESHOT warning | FAIL: warning only | - | Skip |
| CVE-2026-46296 | spi/s3c64xx | NULL deref on driver unbind | FAIL: ARM Samsung | - | Skip |
| CVE-2026-46295 | KVM: x86 APIC | IRR/PIR race causing max_irr=-1 | FAIL: DoS-only (spurious warning) | - | Skip |
| CVE-2026-46294 | dm-ioctl | Buffer overflow in retrieve_status | PASS | 6 | Skip — root-only (DM ioctls need CAP_SYS_ADMIN), limited overflow control |
| CVE-2026-46293 | clk/microchip/mpfs-ccc | OOB access in clock output | FAIL: RISC-V SoC | - | Skip |
| CVE-2026-46292 | pmdomain/genpd | NULL deref in virtual device detach | FAIL: ARM SoC PM | - | Skip |
| CVE-2026-46291 | crypto/caam | HMAC key hex dump debug | FAIL: NXP ARM/PPC | - | Skip |
| CVE-2026-46290 | x86/efi | Fault handler escalates to panic after FPU change | FAIL: DoS-only | - | Skip |
| CVE-2026-46289 | lib/scatterlist | SG entry length overflow in extract_kvec_to_sg | PASS | 8 | Low-medium — deterministic SG overflow but hard to reach from userspace |
| CVE-2026-46288 | of/unittest | UAF in devicetree unittest changeset | FAIL: test code | - | Skip |
| CVE-2026-46287 | net/txgbe | RTNL assertion warning on module remove | FAIL: warning only | - | Skip |
| CVE-2026-46286 | leds/qcom-lpg | OOB read on high-res array index | FAIL: Qualcomm ARM | - | Skip |
| CVE-2026-46285 | mtd/docg3 | UAF in docg3_release | FAIL: MTD DiskOnChip | - | Skip |
| CVE-2026-46284 | mm/hugetlb | Early boot crash on malformed cmdline | FAIL: DoS-only | - | Skip |
| CVE-2026-46283 | tpm | kfree (not kfree_sensitive) for auth session | FAIL: root-only, info leak | - | Skip |
| CVE-2026-46282 | iio/frequency/admv1013 | NULL deref on uninit string | FAIL: IIO driver | - | Skip |
| CVE-2026-46281 | mm/vmalloc (vrealloc) | Linear heap overflow on shrink+realloc | PASS | **10** | **Medium — deterministic overflow, controlled size, but unclear userspace reachability** |
| CVE-2026-46280 | lib/test_hmm | UAF in HMM test module on file close | FAIL: test module | - | Skip |
| CVE-2026-46279 | mm/alloc_tag | Uninitialized codetag warning | FAIL: debug warning | - | Skip |
| CVE-2026-46278 | drm/imagination | NULL deref in ftrace mask debugfs | FAIL: ARM GPU | - | Skip |
| CVE-2026-46277 | mm/zone_device | UAF reading folio->pgmap after folio_free | FAIL: GPU/PMEM HW | - | Skip |
| CVE-2026-46276 | drm/amdgpu | Zero-size GDS range crash on RDNA4 | FAIL: GPU driver | - | Skip |
| **CVE-2026-46275** | **Bluetooth hci_uart** | **Multiple UAF/races in HCI UART lifecycle** | **PASS** | **5** | **Skip — hardware-dependent, no container relevance** |
| **CVE-2026-46274** | **io_uring (io-wq)** | **Dangling hash_tail[0] ptr after cancel → UAF write** | **PASS** | **11** | **HIGH — unpriv UAF write, persistent dangling ptr, wide window** |
| CVE-2026-46273 | ibmveth | GSO freeze on small MSS | FAIL: IBM pSeries | - | Skip |
| CVE-2026-46272 | coresight/tmc-etr | Race between sysfs and perf mode | FAIL: ARM coresight | - | Skip |
| CVE-2026-46271 | wifi/ath12k | FW crash on WoW offload | FAIL: wifi driver | - | Skip |
| CVE-2026-46270 | power/supply/rt9455 | UAF in IRQ vs teardown | FAIL: charger driver | - | Skip |
| CVE-2026-46269 | pinctrl/canaan/k230 | NULL deref in k230 probe | FAIL: RISC-V SoC | - | Skip |
| CVE-2026-46268 | PCI/P2PDMA | Warning condition fix in p2pmem_alloc_mmap | FAIL: warning only | - | Skip |
| CVE-2026-46267 | nfc/hci/shdlc | UAF in timer teardown | FAIL: NFC hardware | - | Skip |
