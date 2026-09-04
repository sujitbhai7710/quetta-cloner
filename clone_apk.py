#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""clone_apk.py - batch APK cloner using QuettaClone.jar (ARSCLib, BFE-matching).

This uses a Java wrapper (QuettaClone.java) that calls ARSCLib directly —
exactly the same API BFE uses (ApkModule, AndroidManifestBlock, setPackageName).
No XML decode/rebuild, no DEX patching. The binary manifest and resources.arsc
are patched in-place, atomically, via ARSCLib.

Flow (mirrors BFE's ApkRewriter.rewrite + renamePackage):
  1. QuettaClone merges splits, patches manifest, renames package (manifest +
     resources.arsc together via module.setPackageName)
  2. Python signs the result with per-clone keystore

Usage:
  python clone_apk.py --apk source.xapk --only "ZetaLite,AcxIrnoy" --out dist
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
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
APKEDITOR_JAR = os.environ.get("APKEDITOR_JAR", "APKEditor.jar")
# QuettaClone.jar is built from QuettaClone.java (committed to repo)
QUETTA_CLONE_JAR = os.environ.get("QUETTA_CLONE_JAR",
    str(Path(__file__).parent / "QuettaClone.jar"))


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


def build_clone(source_path, name, suffix, out_dir, keystore,
                ks_pass, ks_alias, key_pass, tmp_root):
    """Build a single clone using QuettaClone.jar (ARSCLib, BFE-matching)."""
    new_pkg = "net.quetta.browser." + suffix
    stem = safe_filename(name)

    # Run QuettaClone (merge + manifest patch + package rename, all in Java via ARSCLib)
    unsigned_apk = tmp_root / (stem + "_unsigned.apk")
    if unsigned_apk.exists():
        unsigned_apk.unlink()

    cmd = ["java", "-cp", ".:" + APKEDITOR_JAR + ":" + QUETTA_CLONE_JAR,
           "QuettaClone",
           str(source_path.resolve()),
           str(unsigned_apk.resolve()),
           new_pkg,
           name]
    r = subprocess.run(cmd, capture_output=True, text=True,
                       cwd=str(Path(__file__).parent))
    if r.returncode != 0 or not unsigned_apk.exists():
        raise RuntimeError("QuettaClone failed for %s:\n%s" % (name, r.stderr + r.stdout))

    # Sign
    sign_apk(str(unsigned_apk), keystore, ks_pass, ks_alias, key_pass)
    ok, msg = verify_apk(str(unsigned_apk))
    if not ok:
        raise RuntimeError("verify failed:\n%s" % msg)

    # Copy to output
    final_path = out_dir / ("%s.apk" % stem)
    if final_path.exists():
        final_path.unlink()
    shutil.move(str(unsigned_apk), str(final_path))

    size_mb = final_path.stat().st_size / 1e6
    return final_path, "pkg=%s (%.1f MB, standalone, signed+verified)" % (new_pkg, size_mb)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Batch APK cloner (BFE-matching ARSCLib logic)")
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

    # Check QuettaClone.jar exists
    if not Path(QUETTA_CLONE_JAR).exists():
        # Try to compile it from .java
        java_src = Path(__file__).parent / "QuettaClone.java"
        if java_src.exists():
            print("Compiling QuettaClone.jar from source...")
            r = subprocess.run(["javac", "-cp", APKEDITOR_JAR, str(java_src)],
                               capture_output=True, text=True,
                               cwd=str(Path(__file__).parent))
            if r.returncode != 0:
                sys.exit("Failed to compile QuettaClone.java:\n%s" % r.stderr)
        else:
            sys.exit("QuettaClone.java not found at %s" % java_src)

    # Check APKEditor
    r = subprocess.run(["java", "-jar", APKEDITOR_JAR, "-h"],
                       capture_output=True, text=True)
    if "APKEditor" not in (r.stdout + r.stderr):
        sys.exit("APKEditor not found at %s" % APKEDITOR_JAR)

    print("source          : %s" % source)
    print("clones to build : %d -> %s" % (len(names), out_dir))
    print("engine          : QuettaClone (ARSCLib, BFE-matching)")
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
