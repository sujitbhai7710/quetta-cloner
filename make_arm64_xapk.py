#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_arm64_xapk.py - swap the native libraries inside an XAPK/base split
set with the arm64 libraries from a donor APK.

Usage:
  python make_arm64_xapk.py <source.xapk> <libs-donor.apk> <out.xapk>

The result is a complete, arm64-only XAPK that can be cloned with clone_apk.py.
"""
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from clone_apk import _align_extra, _entry_alignment, _local_header  # noqa: E402


def _write_entry(zout, name, data, method, info, rawf):
    try:
        name_bytes = name.encode("ascii")
    except UnicodeEncodeError:
        name_bytes = name.encode("utf-8")
    offset = zout.fp.tell()
    zi = zipfile.ZipInfo(name,
                         date_time=info.date_time if info else (2026, 1, 1, 0, 0, 0))
    zi.compress_type = method
    if info is not None:
        zi.external_attr = info.external_attr
        zi.internal_attr = info.internal_attr
        zi.create_system = info.create_system
    if method == zipfile.ZIP_STORED:
        if info is not None:
            align = _entry_alignment(rawf, info, len(name_bytes))
        else:
            align = 4096 if name.endswith(".so") else 4
        if align:
            zi.extra = _align_extra(offset, len(name_bytes), align)
    zout.writestr(zi, data)


def rebuild_base(src_path, arm64_libs, out_path):
    """Rebuild one APK: drop existing lib/ entries, inject the arm64 libs
    (stored + page aligned, as required by extractNativeLibs=false)."""
    with zipfile.ZipFile(src_path) as zin, \
            open(src_path, "rb") as rawf, \
            zipfile.ZipFile(out_path, "w") as zout:
        for info in zin.infolist():
            name = info.filename
            if name.startswith("lib/"):
                continue  # replaced by the arm64 set below
            with zin.open(info) as f:
                data = f.read()
            method = (zipfile.ZIP_STORED
                      if info.compress_type == zipfile.ZIP_STORED
                      else zipfile.ZIP_DEFLATED)
            _write_entry(zout, name, data, method, info, rawf)
        for name in sorted(arm64_libs):
            _write_entry(zout, name, arm64_libs[name], zipfile.ZIP_STORED, None, None)


def main(argv):
    if len(argv) != 4:
        sys.exit("usage: make_arm64_xapk.py <source.xapk> <libs-donor.apk> <out.xapk>")
    xapk, libs_apk, out = Path(argv[1]), Path(argv[2]), Path(argv[3])

    with zipfile.ZipFile(libs_apk) as zl:
        arm64_libs = {n: zl.read(n) for n in zl.namelist()
                      if "/arm64-v8a/" in n and n.endswith(".so")}
    if not arm64_libs:
        sys.exit("donor APK has no arm64-v8a libraries")
    print("arm64 libs from donor: %d" % len(arm64_libs))

    with zipfile.ZipFile(xapk) as zin:
        # the base = the member APK that carries native libraries
        base_name, best = None, -1
        for n in zin.namelist():
            if not n.endswith(".apk"):
                continue
            member = zipfile.ZipFile(zin.open(n))
            lib_size = sum(i.file_size for i in member.infolist()
                           if i.filename.startswith("lib/"))
            if lib_size > best:
                base_name, best = n, lib_size
        if not base_name or best <= 0:
            sys.exit("could not find the base APK (no member has native libs)")
        print("base: %s" % base_name)

        tmp = Path(tempfile.gettempdir()) / ("base_" + Path(base_name).name)
        tmp.write_bytes(zin.read(base_name))

    rebuild_base(tmp, arm64_libs, tmp.with_suffix(".arm64.apk"))
    rebuilt = tmp.with_suffix(".arm64.apk")

    with zipfile.ZipFile(xapk) as zin, \
            zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zout:
        for n in zin.namelist():
            if n == base_name:
                zout.write(rebuilt, arcname=n)
            else:
                zout.writestr(n, zin.read(n))
    rebuilt.unlink()
    tmp.unlink()
    print("wrote %s (%.1f MB)" % (out, out.stat().st_size / 1e6))


if __name__ == "__main__":
    main(sys.argv)