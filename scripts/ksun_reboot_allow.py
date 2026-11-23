#!/usr/bin/env python3
"""Let the KernelSU-Next install call reach __arm64_sys_reboot."""
import pathlib
import sys

ROOT = pathlib.Path(sys.argv[1])
SECCOMP = ROOT / "common" / "kernel" / "seccomp.c"
SETUID = ROOT / "KernelSU" / "kernel" / "hook" / "setuid_hook.c"

SECCOMP_OLD = """\tthis_syscall = sd ? sd->nr :
\t\tsyscall_get_nr(current, current_pt_regs());

\tswitch (mode) {
"""
SECCOMP_NEW = """\tthis_syscall = sd ? sd->nr :
\t\tsyscall_get_nr(current, current_pt_regs());

#if defined(__aarch64__)
\t/* Install magic must reach the reboot kprobe. 142 == __NR_reboot. */
\tif (this_syscall == 142) {
\t\tlong ksu_m1 = 0, ksu_m2 = 0;
\t\tif (sd) {
\t\t\tksu_m1 = (long)sd->args[0];
\t\t\tksu_m2 = (long)sd->args[1];
\t\t} else if (current_pt_regs()) {
\t\t\tksu_m1 = (long)current_pt_regs()->regs[0];
\t\t\tksu_m2 = (long)current_pt_regs()->regs[1];
\t\t}
\t\tif ((int)ksu_m1 == (int)0xDEADBEEF &&
\t\t    (int)ksu_m2 == (int)0xCAFEBABE) {
\t\t\tpr_info_once("ksu_reboot_magic_allowed\\n");
\t\t\treturn 0;
\t\t}
\t}
#endif

\tswitch (mode) {
"""

SETUID_OLD = """int ksu_handle_setresuid(uid_t old_uid, uid_t new_uid)
{
    // we rely on the fact that zygote always call setresuid(3) with same uids

    if (unlikely(is_uid_manager(new_uid))) {
"""
SETUID_NEW = """int ksu_handle_setresuid(uid_t old_uid, uid_t new_uid)
{
    // we rely on the fact that zygote always call setresuid(3) with same uids

    if (current->seccomp.mode == SECCOMP_MODE_FILTER &&
        current->seccomp.filter && current->sighand) {
        spin_lock_irq(&current->sighand->siglock);
        ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        spin_unlock_irq(&current->sighand->siglock);
    }

    if (unlikely(is_uid_manager(new_uid))) {
"""

SUPER = ROOT / "KernelSU" / "kernel" / "supercall" / "supercall.c"
SUPER_INC_OLD = '#include "manager/manager_identity.h"\n'
SUPER_INC_NEW = '#include "manager/manager_identity.h"\n#include "manager/throne_tracker.h"\n'
SUPER_TW_OLD = """    if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
        pr_err("install ksu fd reply err\\n");
        ksu_close_fd(fd);
    }

    kfree(tw);
"""
SUPER_TW_NEW = """    if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
        pr_err("install ksu fd reply err\\n");
        ksu_close_fd(fd);
    }

    track_throne(false);

    kfree(tw);
"""


def patch(path: pathlib.Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        print(f"{label}: already applied")
        return
    if old not in text:
        raise SystemExit(f"{label}: anchor missing in {path}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"{label}: applied")


def main() -> None:
    if not SECCOMP.is_file():
        raise SystemExit(f"missing {SECCOMP}")
    if not SETUID.is_file():
        raise SystemExit(f"missing {SETUID}")
    if not SUPER.is_file():
        raise SystemExit(f"missing {SUPER}")
    patch(SECCOMP, SECCOMP_OLD, SECCOMP_NEW, "seccomp")
    patch(SETUID, SETUID_OLD, SETUID_NEW, "setuid")
    patch(SUPER, SUPER_INC_OLD, SUPER_INC_NEW, "supercall-inc")
    patch(SUPER, SUPER_TW_OLD, SUPER_TW_NEW, "supercall-tw")
    sec = SECCOMP.read_text(encoding="utf-8")
    tw = SUPER.read_text(encoding="utf-8")
    if "ksu_reboot_magic_allowed" not in sec:
        raise SystemExit("seccomp marker missing after patch")
    if "track_throne(false)" not in tw:
        raise SystemExit("throne call missing after patch")
    print("ok")


if __name__ == "__main__":
    main()
