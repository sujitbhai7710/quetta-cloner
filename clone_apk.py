#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""clone_apk.py - batch APK cloner with Build.* device spoofing.

Flow:
  1. QuettaClone.jar (ARSCLib) merges splits + patches manifest + renames package
  2. APKEditor decodes DEX to smali
  3. Patches smali: replaces Build.MODEL/MANUFACTURER/BRAND/etc. with spoofed values
  4. APKEditor rebuilds → patched APK
  5. Signs with per-clone keystore

Device spoofing:
  - Build.* fields (MODEL, MANUFACTURER, BRAND, FINGERPRINT, etc.) are patched
    in smali — every sget-object is replaced with const-string of a per-clone
    spoofed value. This is what AppCloner does.
  - ANDROID_ID is already unique per signing key (Android 8+), no patching needed.
  - IMEI/SIM/MAC are already blocked by the OS (Android 10+), no patching needed.
  - Play Integrity cannot be bypassed for re-signed APKs — documented limitation.
"""

import argparse
import hashlib
import os
import random
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
QUETTA_CLONE_JAR = os.environ.get("QUETTA_CLONE_JAR",
    str(Path(__file__).parent / "QuettaClone.jar"))


# ── Device profile generator ──

# Realistic device profiles for spoofing
DEVICE_PROFILES = [
    {"brand": "samsung", "manufacturer": "samsung", "model": "SM-S921B",
     "device": "e1q", "product": "e1qsqw", "board": "s5e9945",
     "fingerprint": "samsung/e1qsqw/e1q:14/UP1A.231005.007/S921BXXU3AXJ1:user/release-keys"},
    {"brand": "google", "manufacturer": "Google", "model": "Pixel 8 Pro",
     "device": "husky", "product": "husky", "board": "shiba",
     "fingerprint": "google/husky/husky:14/UQ1A.240205.004/11341893:user/release-keys"},
    {"brand": "OnePlus", "manufacturer": "OnePlus", "model": "CPH2581",
     "device": "OP595DL1", "product": "OP595DL1", "board": "kalama",
     "fingerprint": "OnePlus/OP595DL1/OP595DL1:14/UKQ1.230924.001/T.1106PP.1:user/release-keys"},
    {"brand": "Xiaomi", "manufacturer": "Xiaomi", "model": "23116PN5BC",
     "device": "missi", "product": "missi", "board": "missi",
     "fingerprint": "Xiaomi/missi/missi:14/UKQ1.230804.001/V816.0.5.0.UNACNXM:user/release-keys"},
    {"brand": "vivo", "manufacturer": "vivo", "model": "V2324A",
     "device": "PD2324", "product": "PD2324", "board": "mt6985",
     "fingerprint": "vivo/PD2324/PD2324:14/UKQ1.230917.001/compiler02212123:user/release-keys"},
    {"brand": "OPPO", "manufacturer": "OPPO", "model": "CPH2611",
     "device": "OP5FCDL1", "product": "OP5FCDL1", "board": "kalama",
     "fingerprint": "OPPO/OP5FCDL1/OP5FCDL1:14/UKQ1.230924.001/T.R4W9.1711953347-1:user/release-keys"},
    {"brand": "realme", "manufacturer": "realme", "model": "RMX3900",
     "device": "RE58C2L1", "product": "RE58C2L1", "board": "mt6985",
     "fingerprint": "realme/RE58C2L1/RE58C2L1:14/UKQ1.230917.001/S.R4W9.1711953347-1:user/release-keys"},
    {"brand": "motorola", "manufacturer": "motorola", "model": "XT2347-2",
     "device": "penang", "product": "penang_g", "board": "mt6768",
     "fingerprint": "motorola/penang_g/penang:14/U1SQS34.32-25-5-2/38e9d:user/release-keys"},
    {"brand": "asus", "manufacturer": "asus", "model": "ASUS_AI2302",
     "device": "AI2302", "product": "WW_AI2302", "board": "s5e8835",
     "fingerprint": "asus/WW_AI2302/AI2302:14/UKQ1.230917.001/34.1420.2310.71-0:user/release-keys"},
    {"brand": "Sony", "manufacturer": "Sony", "model": "XQ-CT72",
     "device": "pdx23453", "product": "pdx23453", "board": "mt6985",
     "fingerprint": "Sony/pdx23453/pdx23453:14/UKQ1.230917.001/64.1.A.0.960:user/release-keys"},
]


def generate_build_props(clone_name):
    """Generate deterministic-but-unique Build.* values for a clone.
    Seeded from the clone name so each clone always gets the same profile."""
    seed = int(hashlib.md5(clone_name.encode()).hexdigest(), 16)
    rng = random.Random(seed)
    profile = dict(rng.choice(DEVICE_PROFILES))
    # Add clone-specific uniqueness to the model
    profile["model"] = profile["model"] + "-" + clone_name[:4].upper()
    profile["serial"] = "%016x" % rng.getrandbits(64)
    profile["host"] = "build-%s" % clone_name[:8]
    profile["user"] = "android-build"
    profile["type"] = "user"
    profile["tags"] = "release-keys"
    profile["incremental"] = str(rng.randint(100000, 999999))
    profile["display"] = profile["model"]
    return profile


# ── Smali patcher ──

# Build.* fields to patch (field name → spoofed value key)
BUILD_FIELDS = {
    "MODEL": "model",
    "MANUFACTURER": "manufacturer",
    "BRAND": "brand",
    "DEVICE": "device",
    "PRODUCT": "product",
    "HARDWARE": "board",
    "BOARD": "board",
    "FINGERPRINT": "fingerprint",
    "DISPLAY": "display",
    "HOST": "host",
    "USER": "user",
    "ID": "incremental",
    "SERIAL": "serial",
    "BOOTLOADER": "board",
    "TAGS": "tags",
    "TYPE": "type",
    "INCREMENTAL": "incremental",
}

# Build.VERSION.* fields
VERSION_FIELDS = {
    "RELEASE": "release",
    "INCREMENTAL": "incremental",
    "CODENAME": "codename",
    "SECURITY_PATCH": "security_patch",
}


def patch_smali_file(smali_path, props):
    """Patch a single .smali file: replace Build.* sget-object with const-string."""
    try:
        text = smali_path.read_text(encoding="utf-8", errors="surrogateescape")
        original = text
        patches = 0

        # Patch Build.* fields
        for field, key in BUILD_FIELDS.items():
            if key not in props:
                continue
            val = props[key]
            # Match: sget-object v0, Landroid/os/Build;->MODEL:Ljava/lang/String;
            # Replace with: const-string v0, "spoofed_value"
            pattern = r'sget-object (v\d+|p\d+), Landroid/os/Build;->' + field + r':Ljava/lang/String;'
            replacement = 'const-string \\1, "%s"' % val
            new_text = re.sub(pattern, replacement, text)
            if new_text != text:
                patches += len(re.findall(pattern, text))
                text = new_text

        # Patch Build.VERSION.* fields
        for field, key in VERSION_FIELDS.items():
            if key not in props:
                continue
            val = props[key]
            pattern = r'sget-object (v\d+|p\d+), Landroid/os/Build\$VERSION;->' + field + r':Ljava/lang/String;'
            replacement = 'const-string \\1, "%s"' % val
            new_text = re.sub(pattern, replacement, text)
            if new_text != text:
                patches += len(re.findall(pattern, text))
                text = new_text

        if patches > 0:
            smali_path.write_text(text, encoding="utf-8", errors="surrogateescape")
            return patches
        return 0
    except Exception:
        return 0


def patch_build_props_in_apk(apk_path, clone_name, tmp_root):
    """Decode APK, patch Build.* in smali, rebuild."""
    props = generate_build_props(clone_name)
    props["release"] = "14"
    props["codename"] = "REL"
    props["security_patch"] = "2024-10-05"

    decoded = Path(tempfile.mkdtemp(prefix="smali_", dir=str(tmp_root))).resolve()

    # Decode with APKEditor
    r = subprocess.run(
        ["java", "-jar", APKEDITOR_JAR, "d", "-t", "xml",
         "-i", str(apk_path), "-o", str(decoded), "-f"],
        capture_output=True, text=True)
    if r.returncode != 0:
        shutil.rmtree(decoded, ignore_errors=True)
        raise RuntimeError("APKEditor decode failed:\n%s" % (r.stderr + r.stdout))

    # Patch all smali files
    total_patches = 0
    for smali_file in decoded.rglob("*.smali"):
        total_patches += patch_smali_file(smali_file, props)

    if total_patches == 0:
        shutil.rmtree(decoded, ignore_errors=True)
        return 0, props

    # Rebuild
    patched_apk = apk_path.with_suffix(".patched.apk")
    r = subprocess.run(
        ["java", "-jar", APKEDITOR_JAR, "b",
         "-i", str(decoded), "-o", str(patched_apk), "-f"],
        capture_output=True, text=True)
    shutil.rmtree(decoded, ignore_errors=True)
    if r.returncode != 0 or not patched_apk.exists():
        raise RuntimeError("APKEditor build failed:\n%s" % (r.stderr + r.stdout))

    # Replace original with patched
    shutil.move(str(patched_apk), str(apk_path))
    return total_patches, props


# ── Core build functions ──

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
    """Build a single clone with Build.* spoofing."""
    new_pkg = "net.quetta.browser." + suffix
    stem = safe_filename(name)

    # Step 1: QuettaClone.jar (merge + manifest + rename)
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

    # Step 2: Patch Build.* fields in smali
    patches, props = patch_build_props_in_apk(unsigned_apk, name, tmp_root)

    # Step 3: Sign
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
    device = props.get("model", "?")[:20]
    info = "pkg=%s (%.1f MB, %d props patched, device=%s, signed)" % (
        new_pkg, size_mb, patches, device)
    return final_path, info


def main(argv=None):
    ap = argparse.ArgumentParser(description="Batch APK cloner with Build.* spoofing")
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

    # Check tools
    r = subprocess.run(["java", "-jar", APKEDITOR_JAR, "-h"],
                       capture_output=True, text=True)
    if "APKEditor" not in (r.stdout + r.stderr):
        sys.exit("APKEditor not found at %s" % APKEDITOR_JAR)

    if not Path(QUETTA_CLONE_JAR).exists():
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

    print("source          : %s" % source)
    print("clones to build : %d -> %s" % (len(names), out_dir))
    print("features        : merge + manifest rename + Build.* spoofing + sign")
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
