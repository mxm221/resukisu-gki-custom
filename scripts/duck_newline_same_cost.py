#!/usr/bin/env python3
"""Equalize Duck app_zygote attr/current A/B timing inside selinux_hide.

Duck 2026.10.25 treats a positive median(A-B) as SELinux Danger.
A = "u:r:__selinux_hide_probe_invalid__:s0" (unknown type, conversion EINVAL).
B = same bytes with a leading newline (conversion skipped, empty SID EINVAL).
Run the same conversion on a copy of B before the original newline path.
Do not change return codes. Fail the build if the anchor is missing.
"""
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
CANDIDATES = [
    ROOT / "KernelSU" / "kernel" / "feature" / "selinux_hide.c",
    ROOT / "common" / "drivers" / "kernelsu" / "feature" / "selinux_hide.c",
]
path = next((p for p in CANDIDATES if p.is_file()), None)
if path is None:
    sys.exit(f"selinux_hide.c not found under {ROOT}")

text = path.read_text(encoding="utf-8")
anchor = "    /* Obtain a SID for the context, if one was specified. */\n"
count = text.count(anchor)
if count != 1:
    sys.exit(f"anchor count {count} in {path}, refuse to patch")

block = """    /* ksu_duck_newline_same_cost: Duck app_zygote timing. A positive A-B
     * median is Danger. B skips conversion because it starts with a newline.
     * Convert a same-length copy first, then keep the original EINVAL path. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || defined(KSU_COMPAT_HAS_SELINUX_POLICY_STRUCT)
    if (size && str[0] == '\\n' && size < 256) {
        char same[256];
        u32 duck_sid = 0, duck_tmp = 0;
        int duck_err = 0, duck_rc;

        memcpy(same, str, size);
        same[0] = 'u';
        same[size] = '\\0';
        duck_rc = security_context_to_sid_with_policy(backup_sepolicy, same, size, &duck_tmp, SECSID_NULL,
                                                      GFP_KERNEL, &duck_sid, &duck_err);
        (void)duck_rc;
    }
#endif
"""
if "ksu_duck_newline_same_cost" in text:
    sys.exit("marker already present, refuse to double-patch")

path.write_text(text.replace(anchor, block + anchor, 1), encoding="utf-8")
patched = path.read_text(encoding="utf-8")
if patched.count("ksu_duck_newline_same_cost") != 1:
    sys.exit("marker missing after write")
print(f"patched {path}")
