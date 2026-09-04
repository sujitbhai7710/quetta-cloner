#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""clone_apk.py - batch APK cloner (BFE-matching logic, ARSCLib-based).

Mirrors exactly what BFE's ApkRewriter does:
  - Merges split APKs into a single standalone APK (APKEditor merge)
  - Decodes to XML manifest + resources (APKEditor decode)
  - Patches ONLY the manifest XML (package, permissions, authorities, label,
    taskAffinity) — does NOT touch DEX/smali
  - Patches strings.xml for app label
  - Builds back (APKEditor build) — ARSCLib handles resources.arsc rename
  - Signs with per-clone persistent keystore

CRITICAL: We do NOT patch smali. BFE proved that patching only the manifest
is enough. Patching DEX string literals breaks Class.forName() calls and
other reflection, causing delayed crashes (30-40s after launch).
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
    return found if found else name


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
    return sorted(cands, key=lambda p: p.name)[0] if cands else None


def sanitize_suffix(name):
    s = re.sub(r"[^a-z0-9_]", "_", name.lower())
    s = re.sub(r"_+", "_", s).strip("_") or "clone"
    return s if re.match(r"^[a-z]", s) else "app" + s


def safe_filename(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def load_names(path):
    names, seen = [], set()
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        n = line.strip()
        if n and n not in seen:
            seen.add(n); names.append(n)
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
    res = subprocess.run([APKSIGNER, "verify", "--min-sdk-version", "21", apk_path],
                         capture_output=True, text=True)
    return res.returncode == 0, (res.stdout + res.stderr).strip()


def zipalign_apk(apk_path):
    tmp = str(apk_path) + ".aligned"
    run([ZIPALIGN, "-f", "4", str(apk_path), tmp])
    shutil.move(tmp, str(apk_path))


def apkeditor_merge(input_path, output_path):
    r = subprocess.run(["java", "-jar", APKEDITOR_JAR, "m", "-i", str(input_path),
                       "-o", str(output_path), "-f"],
                      capture_output=True, text=True)
    if r.returncode != 0 or not Path(output_path).exists():
        raise RuntimeError("APKEditor merge failed:\n%s" % (r.stderr + r.stdout))


def apkeditor_decode(input_path, output_dir):
    r = subprocess.run(["java", "-jar", APKEDITOR_JAR, "d", "-t", "xml",
                        "-i", str(input_path), "-o", str(output_dir), "-f"],
                       capture_output=True, text=True)
    if r.returncode != 0 or not (Path(output_dir) / "AndroidManifest.xml").exists():
        raise RuntimeError("APKEditor decode failed:\n%s" % (r.stderr + r.stdout))


def apkeditor_build(input_dir, output_path):
    r = subprocess.run(["java", "-jar", APKEDITOR_JAR, "b", "-i", str(input_dir),
                        "-o", str(output_path), "-f"],
                       capture_output=True, text=True)
    if r.returncode != 0 or not Path(output_path).exists():
        raise RuntimeError("APKEditor build failed:\n%s" % (r.stderr + r.stdout))


def patch_manifest_xml(manifest_path, old_pkg, new_pkg, clone_label):
    """Patch the decoded AndroidManifest.xml (plain XML).

    Exactly mirrors BFE's ApkRewriter.renamePackage():
    1. Provider authorities re-prefixed
    2. Permission declarations re-prefixed
    3. Permission references (android:permission etc.) re-prefixed
    4. taskAffinity re-prefixed
    5. Package name renamed

    Does NOT touch component class names (they're already absolute in Quetta).
    Does NOT touch sharedUserId (Quetta doesn't use it).
    """
    text = manifest_path.read_text(encoding="utf-8", errors="surrogateescape")

    # Use placeholder to avoid double-replacement
    # Phase 1: replace old package with placeholder
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
                r'\g<1>%s\g<2>' % re.escape(clone_label), text)
            text = re.sub(
                r'(<string name="app_name">)(?!@string)[^<]*(</string>)',
                r'\g<1>%s\g<2>' % re.escape(clone_label), text)
            strings_xml.write_text(text, encoding="utf-8", errors="surrogateescape")
        except Exception:
            pass


def patch_resources_arsc_package(decoded_dir, old_pkg, new_pkg):
    """Patch the resources.arsc package name.

    CRITICAL: Chromium's renderer uses the resources.arsc package name to look
    up @0x7f... resources. If the manifest says 'net.quetta.browser.zetalite'
    but resources.arsc says 'net.quetta.browser', the renderer can't find
    resources -> 'Aw Snap' / 'Can't open page' / renderer crash.

    BFE does this via ApkModule.setPackageName() which renames both manifest
    AND resources.arsc. We replicate it by patching:
      - resources/*/package.json (package_name field)
      - resources/*/res/values/public.xml (package="..." attribute)
    """
    # Patch package.json files
    for pkg_json in decoded_dir.rglob("package.json"):
        try:
            text = pkg_json.read_text(encoding="utf-8", errors="surrogateescape")
            text = text.replace(
                '"package_name": "%s"' % old_pkg,
                '"package_name": "%s"' % new_pkg)
            pkg_json.write_text(text, encoding="utf-8", errors="surrogateescape")
        except Exception:
            pass

    # Patch public.xml files (the package="..." attribute on <resources>)
    for public_xml in decoded_dir.rglob("public.xml"):
        try:
            text = public_xml.read_text(encoding="utf-8", errors="surrogateescape")
            text = text.replace(
                'package="%s" id=' % old_pkg,
                'package="%s" id=' % new_pkg)
            public_xml.write_text(text, encoding="utf-8", errors="surrogateescape")
        except Exception:
            pass


def build_clone(source_path, name, suffix, out_dir, keystore,
                ks_pass, ks_alias, key_pass, tmp_root):
    """Build a single clone. Mirrors BFE's ApkRewriter.rewrite()."""
    is_split = source_path.suffix.lower() in (".xapk", ".apks", ".apkm", ".zip")

    # Step 1: Merge to single APK (handles splits + Play markers)
    if is_split:
        merged = tmp_root / (suffix + "_merged.apk")
        if not merged.exists():
            apkeditor_merge(source_path, merged)
        work_apk = merged
    else:
        work_apk = source_path

    # Detect old package
    r = subprocess.run([AAPT2, "dump", "badging", str(work_apk)],
                       capture_output=True, text=True)
    m = re.search(r"^package: name='([^']+)'", r.stdout)
    old_pkg = m.group(1) if m else "net.quetta.browser"
    new_pkg = old_pkg + "." + suffix

    # Step 2: Decompile to XML (manifest + resources, NOT smali-only)
    decoded = Path(tempfile.mkdtemp(prefix="decoded_", dir=str(tmp_root))).resolve()
    apkeditor_decode(work_apk, decoded)

    # Step 3: Patch manifest XML (package, permissions, authorities, label, taskAffinity)
    manifest = decoded / "AndroidManifest.xml"
    if manifest.is_file():
        patch_manifest_xml(manifest, old_pkg, new_pkg, name)

    # Step 4: Patch strings.xml (app label)
    patch_strings_xml(decoded, name)

    # Step 5: Patch resources.arsc package name (CRITICAL for Chromium renderer)
    patch_resources_arsc_package(decoded, old_pkg, new_pkg)

    # Step 6: Build APK (ARSCLib handles resources.arsc package rename via build)
    out_apk = (tmp_root / (safe_filename(name) + ".apk")).resolve()
    if out_apk.exists():
        out_apk.unlink()
    apkeditor_build(decoded, out_apk)

    # Step 7: Zipalign + sign
    zipalign_apk(out_apk)
    sign_apk(str(out_apk), keystore, ks_pass, ks_alias, key_pass)
    ok, msg = verify_apk(str(out_apk))
    if not ok:
        raise RuntimeError("verify failed:\n%s" % msg)

    # Copy to output
    final_path = out_dir / ("%s.apk" % safe_filename(name))
    if final_path.exists():
        final_path.unlink()
    shutil.copy2(out_apk, final_path)

    # Cleanup
    shutil.rmtree(decoded, ignore_errors=True)
    out_apk.unlink(missing_ok=True)
    if is_split:
        merged.unlink(missing_ok=True)

    size_mb = final_path.stat().st_size / 1e6
    return final_path, "pkg=%s (%.1f MB, standalone, signed+verified)" % (new_pkg, size_mb)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Batch APK cloner (BFE-matching logic)")
    ap.add_argument("--apk", help="source APK / .apks / .xapk / .apkm")
    ap.add_argument("--names-file", default="names.txt")
    ap.add_argument("--only", help="comma-separated subset")
    ap.add_argument("--count", type=int, default=0)
    ap.add_argument("--out", default="dist")
    ap.add_argument("--keystore", default="keystore/clone.keystore")
    ap.add_argument("--ks-pass", default="android")
    ap.add_argument("--ks-alias", default="clonekey")
    ap.add_argument("--key-pass", default="android")
    ap.add_argument("--jobs", type=int, default=1)
    args = ap.parse_args(argv)

    source = find_source_apk(args.apk)
    if source is None or not source.is_file():
        sys.exit("source APK not found - pass --apk path/to/Quetta.xapk")

    if args.only:
        names = [n.strip() for n in args.only.split(",") if n.strip()]
    elif Path(args.names_file).is_file():
        names = load_names(args.names_file)
    else:
        sys.exit("names file not found: %s" % args.names_file)
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

    r = subprocess.run(["java", "-jar", APKEDITOR_JAR, "-h"],
                       capture_output=True, text=True)
    if "APKEditor" not in (r.stdout + r.stderr):
        sys.exit("APKEditor not found at %s" % APKEDITOR_JAR)

    print("source          : %s" % source)
    print("clones to build : %d -> %s" % (len(names), out_dir))
    print("output format   : single standalone .apk (no SAI, no DEX patching — BFE logic)")
    print()

    def build_one(task):
        i, name = task
        try:
            suffix = sanitize_suffix(name)
            out_path, info = build_clone(
                source, name, suffix, out_dir,
                args.keystore, args.ks_pass, args.ks_alias, args.key_pass, tmp_dir)
            return i, name, out_path, "[%2d/%d] %-24s %s" % (i, len(names), name, info), None
        except Exception as exc:
            return i, name, None, "", exc

    built = [None] * len(names)
    workers = max(1, min(args.jobs, len(names))) if args.jobs > 0 else 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for i, name, out_path, line, err in pool.map(build_one, enumerate(names, 1)):
            if err is None:
                print(line); built[i - 1] = out_path
            else:
                print("[%2d/%d] %-24s FAILED: %s" % (i, len(names), name, err))

    for f in tmp_dir.iterdir():
        shutil.rmtree(f, ignore_errors=True) if f.is_dir() else f.unlink()
    tmp_dir.rmdir()

    failed = [n for n, b in zip(names, built) if b is None]
    if failed:
        sys.exit("\nfailed clones: " + ", ".join(failed))

    sums = out_dir / "SHA256SUMS.txt"
    with sums.open("w") as fh:
        for p in built:
            h = hashlib.sha256()
            with p.open("rb") as f:
                for block in iter(lambda: f.read(1 << 20), b""):
                    h.update(block)
            fh.write("%s  %s\n" % (h.hexdigest(), p.name))
    print("\nDone: %d clone(s) in %s" % (len(built), out_dir))


if __name__ == "__main__":
    main()
