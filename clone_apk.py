#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""clone_apk.py - batch APK cloner using APKEditor (ARSCLib-based).

For every name in names.txt it produces a signed clone of the source APK:

  * application id      : <original-package>.<lowercased clone name>
  * app label           : the clone name exactly as written in names.txt
  * provider authorities: re-prefixed with the new package
  * permission names    : re-prefixed (both declarations AND references)
  * taskAffinity        : re-prefixed for per-clone task separation
  * Play split markers  : stripped (handled by APKEditor merge)
  * DEX code            : string literals patched (class refs left alone)
  * Output              : single standalone .apk (no SAI needed!)
  * Signature           : re-signed (v1+v2+v3) with per-clone keystore

This uses APKEditor (https://github.com/REAndroid/APKEditor) which is built
on ARSCLib - the same library BFE uses for its APK cloner feature.

Flow:
  1. APKEditor merge: xapk/apks/apkm → single standalone APK
     (auto-strips isSplitRequired, requiredSplitTypes, Play meta-data,
     merges all splits into one APK)
  2. APKEditor decode: APK → XML manifest + smali + resources
  3. Patch AndroidManifest.xml (package, permissions, authorities, label, etc.)
  4. Patch strings.xml (app_cloak_name → clone name)
  5. Patch smali (string literals only, NOT class refs)
  6. APKEditor build: patched XML/smali → APK
  7. zipalign + sign with per-clone keystore
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


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
APKEDITOR_JAR = os.environ.get("APKEDITOR_JAR", "APKEditor.jar")


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


def apkeditor_merge(input_path, output_path):
    """Merge split APKs (xapk/apks/apkm) → single standalone APK.
    Also sanitizes manifest (removes Play split markers)."""
    r = subprocess.run(["java", "-jar", APKEDITOR_JAR, "m", "-i", str(input_path),
                       "-o", str(output_path), "-f"],
                      capture_output=True, text=True)
    if r.returncode != 0 or not Path(output_path).exists():
        raise RuntimeError("APKEditor merge failed:\n%s" % (r.stderr + r.stdout))


def apkeditor_decode(input_path, output_dir):
    """Decompile APK to XML manifest + smali + resources."""
    r = subprocess.run(["java", "-jar", APKEDITOR_JAR, "d", "-t", "xml",
                        "-i", str(input_path), "-o", str(output_dir), "-f"],
                       capture_output=True, text=True)
    if r.returncode != 0 or not (Path(output_dir) / "AndroidManifest.xml").exists():
        raise RuntimeError("APKEditor decode failed:\n%s" % (r.stderr + r.stdout))


def apkeditor_build(input_dir, output_path):
    """Build APK from decompiled directory."""
    r = subprocess.run(["java", "-jar", APKEDITOR_JAR, "b", "-i", str(input_dir),
                        "-o", str(output_path), "-f"],
                       capture_output=True, text=True)
    if r.returncode != 0 or not Path(output_path).exists():
        raise RuntimeError("APKEditor build failed:\n%s" % (r.stderr + r.stdout))


def patch_manifest_xml(manifest_path, old_pkg, new_pkg, clone_label):
    """Patch the decoded AndroidManifest.xml (plain XML)."""
    text = manifest_path.read_text(encoding="utf-8", errors="surrogateescape")
    # Use placeholder to avoid double-replacement
    text = text.replace(old_pkg + ".", "__PKG_DOT__.")
    text = text.replace(old_pkg + ";", "__PKG_DOT__;")
    text = text.replace(old_pkg + '"', '__PKG_DOT__"')
    text = text.replace('package="' + old_pkg + '"', 'package="__PKG_DOT__"')
    # Phase 2: replace placeholder with new package
    text = text.replace("__PKG_DOT__", new_pkg)
    manifest_path.write_text(text, encoding="utf-8", errors="surrogateescape")


def patch_strings_xml(decoded_dir, clone_label):
    """Patch app_cloak_name and app_name in all strings.xml files."""
    for strings_xml in decoded_dir.rglob("strings.xml"):
        try:
            text = strings_xml.read_text(encoding="utf-8", errors="surrogateescape")
            text = re.sub(
                r'(<string name="app_cloak_name">)[^<]*(</string>)',
                r'\g<1>%s\g<2>' % re.escape(clone_label),
                text)
            text = re.sub(
                r'(<string name="app_name">)(?!@string)[^<]*(</string>)',
                r'\g<1>%s\g<2>' % re.escape(clone_label),
                text)
            strings_xml.write_text(text, encoding="utf-8", errors="surrogateescape")
        except Exception:
            pass


def patch_smali_only(decoded_dir, old_pkg, new_pkg):
    """Patch ONLY string literals in smali files. Do NOT move class files
    and do NOT patch Lnet/quetta/browser/ class references.

    CRITICAL: Java class paths (Lnet/quetta/browser/Foo;) must stay unchanged
    because the manifest's android:name attributes reference classes by their
    original FQCN. If we move the class files, the manifest can't find them
    -> ClassNotFoundException -> instant crash on launch.
    """
    old_pkg_dot = old_pkg
    new_pkg_dot = new_pkg

    # Phase 1: replace old package with placeholder in STRING LITERALS only.
    for smali_file in decoded_dir.rglob("*.smali"):
        text = smali_file.read_text(encoding="utf-8", errors="surrogateescape")
        text = text.replace('"' + old_pkg_dot + '.', '"__PKG_DOT__.')
        text = text.replace('"' + old_pkg_dot + ';', '"__PKG_DOT__;')
        text = text.replace('"' + old_pkg_dot + '"', '"__PKG_DOT__"')
        smali_file.write_text(text, encoding="utf-8", errors="surrogateescape")

    # Phase 2: replace placeholder with new package
    for smali_file in decoded_dir.rglob("*.smali"):
        text = smali_file.read_text(encoding="utf-8", errors="surrogateescape")
        text = text.replace('__PKG_DOT__', new_pkg_dot)
        smali_file.write_text(text, encoding="utf-8", errors="surrogateescape")


def build_clone(source_path, name, suffix, out_dir, keystore,
                ks_pass, ks_alias, key_pass, tmp_root):
    """Build a single clone. Returns (out_path, info_line)."""
    # Detect old package from source
    is_split = source_path.suffix.lower() in (".xapk", ".apks", ".apkm", ".zip")

    if is_split:
        # Merge to single APK first
        merged_apk = tmp_root / (suffix + "_merged.apk")
        if not merged_apk.exists():
            apkeditor_merge(source_path, merged_apk)
        work_apk = merged_apk
    else:
        work_apk = source_path

    # Detect old package
    r = subprocess.run([AAPT2, "dump", "badging", str(work_apk)],
                       capture_output=True, text=True)
    m = re.search(r"^package: name='([^']+)'", r.stdout)
    old_pkg = m.group(1) if m else "net.quetta.browser"
    new_pkg = old_pkg + "." + suffix

    stem = safe_filename(name)

    # Decompile to XML + smali
    decoded = Path(tempfile.mkdtemp(prefix="decoded_", dir=str(tmp_root))).resolve()
    apkeditor_decode(work_apk, decoded)

    # Patch manifest
    manifest = decoded / "AndroidManifest.xml"
    if manifest.is_file():
        patch_manifest_xml(manifest, old_pkg, new_pkg, name)

    # Patch strings.xml (app label)
    patch_strings_xml(decoded, name)

    # Patch smali (string literals only)
    patch_smali_only(decoded, old_pkg, new_pkg)

    # Build APK
    out_apk = (tmp_root / (stem + ".apk")).resolve()
    if out_apk.exists():
        out_apk.unlink()
    apkeditor_build(decoded, out_apk)

    # Zipalign + sign
    zipalign_apk(out_apk)
    sign_apk(str(out_apk), keystore, ks_pass, ks_alias, key_pass)
    ok, msg = verify_apk(str(out_apk))
    if not ok:
        raise RuntimeError("apksigner verify failed:\n%s" % msg)

    # Copy to output
    final_path = out_dir / ("%s.apk" % stem)
    if final_path.exists():
        final_path.unlink()
    shutil.copy2(out_apk, final_path)

    # Cleanup
    shutil.rmtree(decoded, ignore_errors=True)
    if is_split:
        merged_apk.unlink(missing_ok=True)
    out_apk.unlink(missing_ok=True)

    size_mb = final_path.stat().st_size / 1e6
    info = "pkg=%s (%.1f MB, standalone APK, signed+verified)" % (new_pkg, size_mb)
    return final_path, info


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Batch APK cloner (APKEditor/ARSCLib-based)")
    ap.add_argument("--apk", help="source APK / .apks / .xapk / .apkm")
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

    source = find_source_apk(args.apk)
    if source is None or not source.is_file():
        sys.exit("source APK not found - pass --apk path/to/Quetta.xapk")

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

    # Check APKEditor (returns exit code 2 for -h, but that's OK)
    r = subprocess.run(["java", "-jar", APKEDITOR_JAR, "-h"],
                       capture_output=True, text=True)
    if "APKEditor" not in (r.stdout + r.stderr):
        sys.exit("APKEditor not found at %s - set APKEDITOR_JAR env var" % APKEDITOR_JAR)

    print("source          : %s" % source)
    print("clones to build : %d -> %s" % (len(names), out_dir))
    print("output format   : single standalone .apk per clone (no SAI needed)")
    print()

    def build_one(task):
        i, name = task
        try:
            suffix = sanitize_suffix(name)
            out_path, info = build_clone(
                source, name, suffix, out_dir,
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

    # Cleanup tmp
    for f in tmp_dir.iterdir():
        if f.is_dir():
            shutil.rmtree(f, ignore_errors=True)
        else:
            f.unlink()
    tmp_dir.rmdir()

    failed = [n for n, b in zip(names, built) if b is None]
    if failed:
        sys.exit("\nfailed clones: " + ", ".join(failed))

    # Checksums
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
