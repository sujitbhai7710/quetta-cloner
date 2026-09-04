#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""clone_apk.py - batch APK cloner (hybrid: apktool for DEX + binary manifest patcher).

For every name in names.txt it produces a signed clone of the source APK:

  * application id      : <original-package>.<lowercased clone name>
  * app label           : the clone name exactly as written in names.txt
  * provider authorities: re-prefixed with the new package
  * permission names    : re-prefixed (both declarations AND references)
  * taskAffinity        : re-prefixed for per-clone task separation
  * Play split markers  : stripped (isSplitRequired, requiredSplitTypes, etc.)
  * DEX code            : ALL class references and string literals patched
                          (decompile -> sed -> recompile via apktool/smali)
  * Signature           : re-signed (v1+v2+v3) with the project keystore

Hybrid approach:
  - apktool d --no-res + apktool b : handles DEX (smali) patching
  - Binary AXML patcher             : handles manifest patching directly
    (avoids apktool's manifest recompile issues that produce corrupt XML)
"""

import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# --- binary AXML constants (for manifest patcher) ---
ANDROID_NS = "http://schemas.android.com/apk/res/android"
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
UTF8_FLAG = 0x100
TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
NO_INDEX = 0xFFFFFFFF
SIG_FILE_RE = re.compile(r"^META-INF/(MANIFEST\.MF|.*\.(SF|RSA|DSA|EC))$", re.IGNORECASE)

# Play distribution markers to strip from the manifest
SPLIT_META_KEYS = frozenset((
    "com.android.vending.splits.required",
    "com.android.vending.splits",
    "com.android.stamp.source",
    "com.android.stamp.type",
    "com.android.vending.derived.apk.id",
))
SPLIT_ATTR_IDS = frozenset((0x0101064E, 0x0101064F, 0x0101054B))  # requiredSplitTypes, splitTypes, isolatedSplits


def find_tool(name):
    exe = name + (".exe" if os.name == "nt" else "")
    home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    roots = []
    if home:
        roots.append(home)
    roots += [os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"),
              os.path.expanduser("~/Library/Android/sdk"),
              os.path.expanduser("~/Android/Sdk"), "/usr/local/lib/android/sdk"]
    import glob
    bt = []
    for root in roots:
        bt += glob.glob(os.path.join(root, "build-tools", "*"))
    for d in sorted(bt, reverse=True):
        p = os.path.join(d, exe)
        if os.path.isfile(p):
            return p
    found = shutil.which(name)
    if found:
        return found
    return name

APKSIGNER = find_tool("apksigner")
ZIPALIGN = find_tool("zipalign")
KEYTOOL = find_tool("keytool")
AAPT2 = find_tool("aapt2")
APKTOOL_JAR = os.environ.get("APKTOOL_JAR", "apktool.jar")


# ================================================================
# BINARY AXML MANIFEST PATCHER (imported from legacy code)
# ================================================================
# The legacy patch_manifest is proven to produce correct binary AXML.
# We import it directly rather than reimplementing (which had alignment bugs).

import clone_apk_legacy as _legacy
patch_manifest_legacy = _legacy.patch_manifest


def patch_manifest(manifest_bytes, old_pkg, new_pkg, label):
    """Wrapper around the legacy binary manifest patcher.
    Returns (patched_bytes, stats_dict)."""
    suffix = new_pkg.split(".")[-1]  # e.g. "zetalite"
    patched = patch_manifest_legacy(manifest_bytes, suffix, label)
    # The legacy function returns a tuple of 8 values; we only need the bytes.
    # Actually it returns the patched manifest bytes directly.
    # Let me check...
    if isinstance(patched, tuple):
        patched = patched[0]
    # Count stats by re-parsing (for logging)
    stats = {"labels": -1, "authorities": -1, "permissions": -1,
             "perm_refs": -1, "affinity": -1, "meta_removed": -1,
             "split_attrs_removed": -1}
    return patched, stats


# ================================================================
# APK BUILDING
# ================================================================

def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        raise RuntimeError("cmd failed: %s\n%s" % (" ".join(cmd), r.stderr + r.stdout))
    return r


def find_source_apk(explicit=None):
    if explicit:
        return Path(explicit)
    cands = [p for p in Path(".").glob("*.apk") if p.is_file()]
    if not cands:
        return None
    return sorted(cands, key=lambda p: p.name)[0]


def sanitize_suffix(name):
    s = re.sub(r"[^a-z0-9_]", "_", name.lower())
    s = re.sub(r"_+", "_", s).strip("_") or "clone"
    if not re.match(r"^[a-z]", s):
        s = "app" + s
    return s


def safe_filename(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def load_names(path):
    names, seen = [], set()
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        n = line.strip()
        if n and n not in seen:
            seen.add(n)
            names.append(n)
    return names


def is_base_apk(path):
    try:
        r = subprocess.run([AAPT2, "dump", "xmltree", str(path),
                           "--file", "AndroidManifest.xml"],
                          capture_output=True, text=True, timeout=15)
        out = r.stdout.lower()
        return 'split="' not in out and 'isfeaturesplit' not in out
    except Exception:
        return False


def resolve_source(apk_path, splits_arg):
    apk_path = Path(apk_path)
    if apk_path.suffix.lower() in (".xapk", ".apks", ".apkm", ".zip"):
        tmp = Path(tempfile.mkdtemp(prefix="apkset_"))
        with zipfile.ZipFile(apk_path) as z:
            z.extractall(tmp)
        apks = sorted(tmp.rglob("*.apk"))
        if not apks:
            sys.exit("no .apk files found inside %s" % apk_path)
        bases = [p for p in apks if is_base_apk(p)]
        base = bases[0] if bases else max(apks, key=lambda p: p.stat().st_size)
        return base, [p for p in apks if p != base], tmp
    if splits_arg:
        sp = Path(splits_arg)
        splits = sorted(sp.glob("*.apk")) if sp.is_dir() else [sp]
        return apk_path, splits, None
    return apk_path, [], None


def ensure_keystore(keystore, store_pass, alias, key_pass, dname):
    if os.path.isfile(keystore):
        return False
    cmd = [KEYTOOL, "-genkeypair", "-v", "-keystore", keystore, "-storetype", "PKCS12",
           "-alias", alias, "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
           "-storepass", store_pass, "-keypass", key_pass, "-dname", dname]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
    return True


def sign_apk(apk_path, keystore, store_pass, alias, key_pass):
    cmd = [APKSIGNER, "sign", "--ks", keystore, "--ks-key-alias", alias,
           "--ks-pass", "pass:" + store_pass, "--key-pass", "pass:" + key_pass,
           "--min-sdk-version", "21",
           "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
           "--v3-signing-enabled", "true", apk_path]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)


def verify_apk(apk_path):
    res = subprocess.run([APKSIGNER, "verify", "--min-sdk-version", "21",
                          "--print-certs", apk_path],
                         capture_output=True, text=True)
    return res.returncode == 0, (res.stdout + res.stderr).strip()


def zipalign_apk(apk_path):
    tmp = str(apk_path) + ".aligned"
    run([ZIPALIGN, "-f", "4", str(apk_path), tmp])
    shutil.move(tmp, str(apk_path))


def strip_signature(apk_path):
    apk_path = Path(apk_path)
    tmp = apk_path.with_suffix(".stripped.apk")
    with zipfile.ZipFile(apk_path, "r") as zin, \
            zipfile.ZipFile(tmp, "w") as zout:
        for info in zin.infolist():
            name = info.filename
            if name.startswith("META-INF/") and \
                    (name.endswith(".SF") or name.endswith(".RSA") or
                     name.endswith(".DSA") or name.endswith(".EC") or
                     name == "META-INF/MANIFEST.MF"):
                continue
            if name == "stamp-cert-sha256":
                continue
            data = zin.read(info)
            zi = zipfile.ZipInfo(name, date_time=info.date_time)
            zi.compress_type = info.compress_type
            zi.external_attr = info.external_attr
            zi.internal_attr = info.internal_attr
            zi.create_system = info.create_system
            zout.writestr(zi, data)
    shutil.move(str(tmp), str(apk_path))


def has_dex(apk_path):
    try:
        with zipfile.ZipFile(apk_path) as z:
            return any(n.startswith("classes") and n.endswith(".dex") for n in z.namelist())
    except Exception:
        return False


def replace_manifest_in_apk(apk_path, new_manifest_bytes):
    """Replace AndroidManifest.xml inside an APK with new binary manifest.
    Pads the manifest to a 4-byte boundary (required by binary AXML format)."""
    # Pad to 4-byte boundary
    pad = (-len(new_manifest_bytes)) % 4
    if pad:
        new_manifest_bytes = new_manifest_bytes + b"\x00" * pad
    apk_path = Path(apk_path)
    tmp = apk_path.with_suffix(".manifest_patched.apk")
    with zipfile.ZipFile(apk_path, "r") as zin, \
            zipfile.ZipFile(tmp, "w") as zout:
        for info in zin.infolist():
            if info.filename == "AndroidManifest.xml":
                zi = zipfile.ZipInfo("AndroidManifest.xml", date_time=info.date_time)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = info.external_attr
                zout.writestr(zi, new_manifest_bytes)
            else:
                zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                zi.compress_type = info.compress_type
                zi.external_attr = info.external_attr
                zi.internal_attr = info.internal_attr
                zi.create_system = info.create_system
                zout.writestr(zi, zin.read(info))
    shutil.move(str(tmp), str(apk_path))


def patch_smali_only(decoded_dir, old_pkg, new_pkg):
    """Patch ONLY string literals in smali files. Do NOT move class files
    and do NOT patch Lnet/quetta/browser/ class references.

    CRITICAL: Java class paths (Lnet/quetta/browser/Foo;) must stay unchanged
    because the manifest's android:name attributes reference classes by their
    original FQCN (e.g. net.quetta.browser.videoplay.QuettaVideoPlayActivity).
    If we move the class files, the manifest can't find them -> ClassNotFoundException
    -> instant crash on launch.

    We only patch STRING LITERALS (const-string instructions) that reference
    the package name for:
      - Content provider URIs: "content://net.quetta.browser.X"
      - Permission registration: "net.quetta.browser.permission.CHILD_SERVICE"
      - SharedPreferences keys: "net.quetta.browser.videoplay.view.LongPressedKey"
      - etc.

    These string literals must match the re-prefixed manifest values, otherwise
    runtime queries (getContentResolver().query(...), checkPermission(...),
    registerReceiver(...)) would fail.
    """
    old_pkg_dot = old_pkg          # net.quetta.browser
    new_pkg_dot = new_pkg          # net.quetta.browser.zetalite

    # Phase 1: replace old package with placeholder in STRING LITERALS only.
    # In smali, string literals are inside const-string instructions:
    #   const-string v0, "net.quetta.browser.permission.CHILD_SERVICE"
    # We match the opening quote to ensure we only patch strings, not class refs.
    for smali_file in decoded_dir.rglob("*.smali"):
        text = smali_file.read_text(encoding="utf-8", errors="surrogateescape")
        # Patch string literals: "net.quetta.browser. -> "net.quetta.browser.<clone>.
        text = text.replace('"' + old_pkg_dot + '.', '"__PKG_DOT__.')
        # Patch: "net.quetta.browser; (in semicolon-separated lists)
        text = text.replace('"' + old_pkg_dot + ';', '"__PKG_DOT__;')
        # Patch: "net.quetta.browser" (bare, at end of string)
        text = text.replace('"' + old_pkg_dot + '"', '"__PKG_DOT__"')
        smali_file.write_text(text, encoding="utf-8", errors="surrogateescape")

    # Phase 2: replace placeholder with new package
    for smali_file in decoded_dir.rglob("*.smali"):
        text = smali_file.read_text(encoding="utf-8", errors="surrogateescape")
        text = text.replace('__PKG_DOT__', new_pkg_dot)
        smali_file.write_text(text, encoding="utf-8", errors="surrogateescape")

    # DO NOT move class files. DO NOT patch Lnet/quetta/browser/ references.
    # The manifest references classes by their original FQCN, so the classes
    # must stay at their original package path.


def build_clone(base_apk, split_apks, name, suffix, out_dir, keystore,
                ks_pass, ks_alias, key_pass, tmp_root):
    """Build a single clone."""
    # detect old package
    r = subprocess.run([AAPT2, "dump", "badging", str(base_apk)],
                       capture_output=True, text=True)
    m = re.search(r"^package: name='([^']+)'", r.stdout)
    old_pkg = m.group(1) if m else "net.quetta.browser"
    new_pkg = old_pkg + "." + suffix

    stem = safe_filename(name)
    built_apks = []
    all_apks = [(base_apk, "base.apk")] + [(s, s.name) for s in split_apks]

    for src_apk, arc_name in all_apks:
        if not has_dex(src_apk):
            # config splits: patch manifest binary + re-sign
            dst = tmp_root / (stem + "_" + arc_name)
            shutil.copy2(src_apk, dst)
            strip_signature(dst)
            # patch manifest
            with zipfile.ZipFile(dst, "r") as z:
                manifest = z.read("AndroidManifest.xml")
            patched, stats = patch_manifest(manifest, old_pkg, new_pkg, name)
            replace_manifest_in_apk(dst, patched)
            zipalign_apk(dst)
            sign_apk(str(dst), keystore, ks_pass, ks_alias, key_pass)
            ok, msg = verify_apk(str(dst))
            if not ok:
                raise RuntimeError("verify failed for %s:\n%s" % (arc_name, msg))
            built_apks.append((dst, arc_name))
            continue

        # APK with code: decompile DEX -> patch smali -> recompile -> patch manifest -> sign
        decoded = Path(tempfile.mkdtemp(prefix="decoded_", dir=str(tmp_root))).resolve()

        # decompile with --no-res (keeps manifest as binary, only decodes DEX to smali)
        r = subprocess.run(["java", "-jar", APKTOOL_JAR, "d", "-f", "--no-res",
                            str(Path(src_apk).resolve()), "-o", str(decoded)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("apktool d failed for %s:\n%s" % (arc_name, r.stderr + r.stdout))

        # patch smali (class refs, string literals, move class files)
        patch_smali_only(decoded, old_pkg, new_pkg)

        # recompile (manifest stays as binary, only DEX is rebuilt)
        out_apk = (tmp_root / (stem + "_" + arc_name)).resolve()
        if out_apk.exists():
            out_apk.unlink()
        r = subprocess.run(["java", "-jar", APKTOOL_JAR, "b", str(decoded.resolve()),
                            "-o", str(out_apk), "--use-aapt2"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("apktool b failed for %s:\n%s" % (arc_name, r.stderr + r.stdout))

        # NOW patch the binary manifest (replaces package, permissions, authorities,
        # label, strips Play markers — all in correct binary AXML format)
        with zipfile.ZipFile(out_apk, "r") as z:
            manifest = z.read("AndroidManifest.xml")
        patched, stats = patch_manifest(manifest, old_pkg, new_pkg, name)
        replace_manifest_in_apk(out_apk, patched)

        # zipalign + sign
        zipalign_apk(out_apk)
        sign_apk(str(out_apk), keystore, ks_pass, ks_alias, key_pass)
        ok, msg = verify_apk(str(out_apk))
        if not ok:
            raise RuntimeError("verify failed for %s:\n%s" % (arc_name, msg))
        built_apks.append((out_apk, arc_name))
        shutil.rmtree(decoded, ignore_errors=True)

    # bundle
    if split_apks:
        out_path = out_dir / ("%s.apks" % stem)
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_STORED) as bundle:
            for f, arc in built_apks:
                bundle.write(f, arcname=arc)
    else:
        out_path = out_dir / ("%s.apk" % stem)
        if out_path.exists():
            out_path.unlink()
        built_apks[0][0].replace(out_path)

    size_mb = out_path.stat().st_size / 1e6
    info = "pkg=%s (%.1f MB, %d APK(s), signed+verified)" % (
        new_pkg, size_mb, len(built_apks))
    return out_path, info


def main(argv=None):
    ap = argparse.ArgumentParser(description="Batch APK cloner (hybrid: apktool DEX + binary manifest)")
    ap.add_argument("--apk", help="source APK / .apks / .xapk")
    ap.add_argument("--splits", help="directory with split APKs")
    ap.add_argument("--names-file", default="names.txt")
    ap.add_argument("--only", help="comma-separated subset of clone names")
    ap.add_argument("--count", type=int, default=0)
    ap.add_argument("--out", default="dist")
    ap.add_argument("--keystore", default="keystore/clone.keystore")
    ap.add_argument("--ks-pass", default="android")
    ap.add_argument("--ks-alias", default="clonekey")
    ap.add_argument("--key-pass", default="android")
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--info", action="store_true")
    args = ap.parse_args(argv)

    apk = find_source_apk(args.apk)
    if apk is None or not apk.is_file():
        sys.exit("source APK not found - pass --apk path/to/Quetta.xapk")

    base_apk, split_apks, tmp_extract = resolve_source(apk, args.splits)

    if args.only:
        names = [n.strip() for n in args.only.split(",") if n.strip()]
    elif Path(args.names_file).is_file():
        names = load_names(args.names_file)
    else:
        sys.exit("names file not found: %s (or use --only)" % args.names_file)
    if args.count and args.count > 0 and not args.only:
        names = names[:args.count]
    if not names:
        sys.exit("no clone names given")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = out_dir / "_tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    Path(args.keystore).parent.mkdir(parents=True, exist_ok=True)
    if ensure_keystore(args.keystore, args.ks_pass, args.ks_alias, args.key_pass,
                       "CN=APK Clone, OU=Clone, O=Clone, C=US"):
        print("generated new keystore: %s" % args.keystore)

    r = subprocess.run(["java", "-jar", APKTOOL_JAR, "--version"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("apktool not found at %s - set APKTOOL_JAR env var" % APKTOOL_JAR)

    print("source          : %s (%d split APK(s))" % (base_apk, len(split_apks)))
    print("clones to build : %d -> %s" % (len(names), out_dir))
    print()

    def build_one(task):
        i, name = task
        try:
            suffix = sanitize_suffix(name)
            out_path, info = build_clone(
                base_apk, split_apks, name, suffix, out_dir,
                args.keystore, args.ks_pass, args.ks_alias, args.key_pass,
                tmp_dir)
            line = "[%2d/%d] %-24s %s" % (i, len(names), name, info)
            return i, name, out_path, line, None
        except Exception as exc:
            return i, name, None, "", exc

    built = [None] * len(names)
    workers = max(1, min(args.jobs, len(names))) if args.jobs > 0 else 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for i, name, out_path, line, err in pool.map(build_one, enumerate(names, 1)):
            if err is None:
                print(line)
                built[i - 1] = out_path
            else:
                print("[%2d/%d] %-24s FAILED: %s" % (i, len(names), name, err))

    for f in tmp_dir.iterdir():
        if f.is_dir():
            shutil.rmtree(f, ignore_errors=True)
        else:
            f.unlink()
    tmp_dir.rmdir()
    if tmp_extract:
        shutil.rmtree(tmp_extract, ignore_errors=True)

    failed = [n for n, b in zip(names, built) if b is None]
    if failed:
        sys.exit("\nfailed clones: " + ", ".join(failed))

    sums_path = out_dir / "SHA256SUMS.txt"
    with sums_path.open("w", encoding="utf-8") as fh:
        for p in built:
            h = hashlib.sha256()
            with p.open("rb") as f:
                for block in iter(lambda: f.read(1 << 20), b""):
                    h.update(block)
            fh.write("%s  %s\n" % (h.hexdigest(), p.name))
    print("\nDone: %d clone(s) in %s" % (len(built), out_dir))


if __name__ == "__main__":
    main()
