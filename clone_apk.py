#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""clone_apk.py - batch APK cloner.

For every name in names.txt it produces a signed clone of the source APK:

  * application id      : <original-package>.<lowercased clone name>
  * app label           : the clone name exactly as written in names.txt
  * provider authorities: re-prefixed with the new package so every clone
                          can be installed side by side.

The APK is patched at the binary level (compiled-XML manifest editing +
raw zip entry copy) - no decompile/recompile - so it is fast, keeps the
original compression/alignment of every entry, and is then re-signed
with apksigner (v1 + v2 schemes).

Usage:
  python clone_apk.py --info
  python clone_apk.py --apk Quetta.apk --names-file names.txt --count 4 --out dist
  python clone_apk.py --apk Quetta.apk --names-file names.txt --out dist   # all names
"""

import argparse
import glob
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ANDROID_NS = "http://schemas.android.com/apk/res/android"
SIG_FILE_RE = re.compile(r"^META-INF/(MANIFEST\.MF|.*\.(SF|RSA|DSA|EC))$", re.IGNORECASE)

# --- binary AXML (compiled AndroidManifest.xml) constants ---
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
UTF8_FLAG = 0x100
TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
NO_INDEX = 0xFFFFFFFF


def _read_pooled_length(data, pos, unit_size):
    """Read an Android string-pool length prefix (escaped-length encoding)."""
    if unit_size == 1:
        b0 = data[pos]
        pos += 1
        if b0 & 0x80:
            return ((b0 & 0x7F) << 8) | data[pos], pos + 1
        return b0, pos
    b0 = struct.unpack_from("<H", data, pos)[0]
    pos += 2
    if b0 & 0x8000:
        return ((b0 & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos)[0], pos + 2
    return b0, pos


def _write_pooled_length(value, unit_size):
    if unit_size == 1:
        if value < 0x80:
            return bytes([value])
        return bytes([((value >> 8) & 0x7F) | 0x80, value & 0xFF])
    if value < 0x8000:
        return struct.pack("<H", value)
    return struct.pack("<HH", ((value >> 16) & 0x7FFF) | 0x8000, value & 0xFFFF)


def parse_string_pool(data, off):
    """Parse a ResStringPool chunk. Returns (strings, is_utf8, chunk_size)."""
    (_ctype, hsize, size, count, style_count, flags,
     strings_start, _styles_start) = struct.unpack_from("<HHIIIIII", data, off)
    if style_count:
        raise NotImplementedError("string pool with styles is not supported")
    utf8 = bool(flags & UTF8_FLAG)
    offsets = struct.unpack_from("<%dI" % count, data, off + hsize) if count else ()
    base = off + strings_start
    strings = []
    for delta in offsets:
        pos = base + delta
        if utf8:
            _u16_units, pos = _read_pooled_length(data, pos, 1)
            u8_len, pos = _read_pooled_length(data, pos, 1)
            strings.append(data[pos:pos + u8_len].decode("utf-8", "surrogateescape"))
        else:
            u16_units, pos = _read_pooled_length(data, pos, 2)
            strings.append(data[pos:pos + 2 * u16_units].decode("utf-16-le", "surrogateescape"))
    return strings, utf8, size


def encode_string_pool(strings, utf8):
    """Serialize a ResStringPool chunk (styles are never used in AXML)."""
    blobs, offsets, pos = [], [], 0
    for s in strings:
        offsets.append(pos)
        if utf8:
            raw = s.encode("utf-8", "surrogateescape")
            u16_units = len(s.encode("utf-16-le", "surrogateescape")) // 2
            blob = (_write_pooled_length(u16_units, 1)
                    + _write_pooled_length(len(raw), 1) + raw + b"\x00")
        else:
            raw = s.encode("utf-16-le", "surrogateescape")
            blob = _write_pooled_length(len(s), 2) + raw + b"\x00\x00"
        blobs.append(blob)
        pos += len(blob)
    strings_data = b"".join(blobs)
    strings_start = 28 + 4 * len(strings)
    total = strings_start + len(strings_data)
    pad = (-total) % 4
    header = struct.pack("<HHIIIIII", RES_STRING_POOL_TYPE, 28, total + pad,
                         len(strings), 0, UTF8_FLAG if utf8 else 0, strings_start, 0)
    index = struct.pack("<%dI" % len(strings), *offsets) if strings else b""
    return header + index + strings_data + b"\x00" * pad


def parse_attributes(raw):
    """Parse the attribute table of a start-element chunk."""
    attr_start, attr_size, attr_count = struct.unpack_from("<HHH", raw, 24)
    base = 16 + attr_start
    attrs = []
    for i in range(attr_count):
        o = base + i * attr_size
        ns, name, raw_value = struct.unpack_from("<III", raw, o)
        tsize = struct.unpack_from("<H", raw, o + 12)[0]
        dtype_off = o + 12 + tsize - 5
        data_off = o + 12 + tsize - 4
        attrs.append({
            "ns": ns, "name": name, "raw_value": raw_value,
            "dtype": raw[dtype_off], "data": struct.unpack_from("<I", raw, data_off)[0],
            "raw_off": o + 8, "dtype_off": dtype_off, "data_off": data_off,
        })
    return attrs


def _set_string_value(chunk, attr, string_index):
    """Point an attribute at a string-pool index (as a STRING typed value)."""
    struct.pack_into("<I", chunk, attr["raw_off"], string_index)
    chunk[attr["dtype_off"]] = TYPE_STRING
    struct.pack_into("<I", chunk, attr["data_off"], string_index)


def _element_tag(strings, raw):
    name_idx = struct.unpack_from("<I", raw, 20)[0]
    if name_idx == NO_INDEX or name_idx >= len(strings):
        return None
    return strings[name_idx]


def split_chunks(manifest):
    """Return (strings, utf8, [(chunk_type, bytearray), ...]) for an AXML doc."""
    strings, utf8, pool_size = parse_string_pool(manifest, 8)
    body = manifest[8 + pool_size:]
    chunks, pos = [], 0
    while pos < len(body):
        ctype, _hsize, csize = struct.unpack_from("<HHI", body, pos)
        chunks.append([ctype, bytearray(body[pos:pos + csize])])
        pos += csize
    return strings, utf8, chunks


def patch_manifest(manifest, suffix, label, extract_libs=True):
    """Patch the compiled AndroidManifest.xml for one clone.

    Returns (new_manifest, old_package, new_package, labels_patched,
    authorities_patched, extract_libs_patched).
    """
    if struct.unpack_from("<H", manifest, 0)[0] != RES_XML_TYPE:
        raise ValueError("AndroidManifest.xml is not a binary AXML document")

    strings, utf8, chunks = split_chunks(manifest)
    pool = list(strings)

    def intern(s):
        try:
            return pool.index(s)
        except ValueError:
            pool.append(s)
            return len(pool) - 1

    start_elements = [c for t, c in chunks if t == RES_XML_START_ELEMENT_TYPE]
    if not start_elements:
        raise ValueError("manifest contains no elements")
    if _element_tag(strings, bytes(start_elements[0])) != "manifest":
        raise ValueError("root element is not <manifest>")

    # ---- 1. <manifest package="..."> ----
    manifest_attrs = parse_attributes(bytes(start_elements[0]))
    pkg_attr = next((a for a in manifest_attrs
                     if a["ns"] == NO_INDEX and a["name"] < len(pool)
                     and pool[a["name"]] == "package"), None)
    if pkg_attr is None:
        raise ValueError("manifest has no package attribute")
    if pkg_attr["dtype"] != TYPE_STRING:
        raise ValueError("package attribute is not a string value")
    old_package = pool[pkg_attr["data"]]
    if not old_package:
        raise ValueError("empty package name")
    new_package = old_package + "." + suffix
    if new_package == old_package:
        raise ValueError("new package name equals the original")
    _set_string_value(start_elements[0], pkg_attr, intern(new_package))

    # ---- 2. android:label + 3. provider android:authorities ----
    label_idx = None
    labels_patched = 0
    authorities_patched = 0
    extract_libs_patched = False
    for chunk in start_elements:
        for a in parse_attributes(bytes(chunk)):
            if (a["ns"] == NO_INDEX or a["ns"] >= len(pool)
                    or pool[a["ns"]] != ANDROID_NS):
                continue
            if a["name"] >= len(pool):
                continue
            name = pool[a["name"]]
            if name == "label" and a["dtype"] in (TYPE_STRING, TYPE_REFERENCE):
                if label_idx is None:
                    label_idx = intern(label)
                _set_string_value(chunk, a, label_idx)
                labels_patched += 1
            elif name == "authorities" and a["dtype"] == TYPE_STRING:
                s = pool[a["data"]]
                # authorities may be a ';'-separated list - re-prefix each one
                new_parts, changed = [], False
                for part in s.split(";"):
                    if part == old_package:
                        new_parts.append(new_package)
                        changed = True
                    elif part.startswith(old_package + "."):
                        new_parts.append(new_package + part[len(old_package):])
                        changed = True
                    else:
                        new_parts.append(part)
                if changed:
                    _set_string_value(chunk, a, intern(";".join(new_parts)))
                    authorities_patched += 1
            elif name == "extractNativeLibs" and a["dtype"] == 0x12:  # INT_BOOLEAN
                # extractNativeLibs=true -> installer extracts libs, removing
                # every page-size/alignment requirement (max compatibility)
                if extract_libs and a["data"] == 0:
                    struct.pack_into("<I", chunk, a["data_off"], 0xFFFFFFFF)  # true
                    extract_libs_patched = True

    pool_blob = encode_string_pool(pool, utf8)

    # ---- 4. drop Play "distribution format" markers -----------------------
    # Play-generated base APKs carry meta-data that forces the installer to
    # demand the config split APKs -> INSTALL_FAILED_MISSING_SPLIT ("app not
    # compatible with your phone"). Removing them makes the base APK install
    # standalone.
    SPLIT_META_KEYS = frozenset((
        "com.android.vending.splits.required",
        "com.android.vending.splits",
        "com.android.stamp.source",
        "com.android.stamp.type",
        "com.android.vending.derived.apk.id",
    ))
    cleaned, removed_meta, i = [], 0, 0
    while i < len(chunks):
        ctype, cbytes = chunks[i]
        if (ctype == RES_XML_START_ELEMENT_TYPE
                and _element_tag(strings, bytes(cbytes)) == "meta-data"):
            name_val = None
            for a in parse_attributes(bytes(cbytes)):
                if (a["ns"] != NO_INDEX and a["ns"] < len(pool)
                        and pool[a["ns"]] == ANDROID_NS
                        and pool[a["name"]] == "name" and a["dtype"] == TYPE_STRING):
                    name_val = pool[a["data"]]
                    break
            if name_val in SPLIT_META_KEYS:
                depth, j = 0, i
                while j < len(chunks):
                    tj = chunks[j][0]
                    if tj == RES_XML_START_ELEMENT_TYPE:
                        depth += 1
                    elif tj == RES_XML_END_ELEMENT_TYPE:
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                removed_meta += 1
                i = j + 1
                continue
        cleaned.append(chunks[i])
        i += 1
    chunks = cleaned

    # ---- 5. strip Play Feature Delivery split attributes from <manifest> ---
    # requiredSplitTypes/splitTypes/isolatedSplits make PackageInstaller treat
    # the base APK as "requires feature-module splits" -> every standalone
    # install fails with INSTALL_FAILED_MISSING_SPLIT. Remove them.
    SPLIT_ATTR_IDS = frozenset((0x0101064E, 0x0101064F, 0x0101054B))
    resmap = None
    for t, c in chunks:
        if t == RES_XML_RESOURCE_MAP_TYPE:
            n = (len(c) - 8) // 4
            resmap = struct.unpack_from("<%dI" % n, c, 8) if n else ()
            break
    mani_chunk = start_elements[0]
    attr_start, attr_size, attr_count = struct.unpack_from("<HHH", bytes(mani_chunk), 24)
    attr_base = 16 + attr_start
    keep_records, removed_positions = [], []
    for ai in range(attr_count):
        off = attr_base + ai * attr_size
        name_idx = struct.unpack_from("<I", mani_chunk, off + 4)[0]
        rid = resmap[name_idx] if (resmap and name_idx < len(resmap)) else 0
        if rid in SPLIT_ATTR_IDS:
            removed_positions.append(ai)
        else:
            keep_records.append(bytes(mani_chunk[off:off + attr_size]))
    split_attrs_removed = len(removed_positions)
    if split_attrs_removed:
        def _adjust(value):
            if value == 0:
                return 0
            if value in removed_positions:
                return 0
            return value - sum(1 for p in removed_positions if p < value)
        new_chunk = bytearray(mani_chunk[:attr_base])
        struct.pack_into("<H", new_chunk, 28, attr_count - split_attrs_removed)
        for pos, key in ((30, "id"), (32, "class"), (34, "style")):
            struct.pack_into("<H", new_chunk, pos,
                             _adjust(struct.unpack_from("<H", new_chunk, pos)[0]))
        for rec in keep_records:
            new_chunk += rec
        struct.pack_into("<I", new_chunk, 4, len(new_chunk))
        new_chunk += b"\x00" * ((-len(new_chunk)) % 4)
        for ci, (t, c) in enumerate(chunks):
            if c is mani_chunk:
                chunks[ci] = [t, new_chunk]
                break

    body_blob = b"".join(bytes(c) for _t, c in chunks)
    total = 8 + len(pool_blob) + len(body_blob)
    out = struct.pack("<HHI", RES_XML_TYPE, 8, total) + pool_blob + body_blob
    return (bytes(out), old_package, new_package, labels_patched,
            authorities_patched, extract_libs_patched, removed_meta,
            split_attrs_removed)


def _local_header(rawf, info):
    rawf.seek(info.header_offset)
    hdr = rawf.read(30)
    sig, _ver, _flags, _method, _mt, _md, _crc, _cs, _us, nlen, elen = \
        struct.unpack("<IHHHHHIIIHH", hdr)
    if sig != 0x04034B50:
        raise ValueError("bad local header: %s" % info.filename)
    return nlen, elen


def _align_extra(offset, name_len, align):
    """zipalign-style padding extra field (id 0xD935) for STORED entries."""
    r = (offset + 30 + name_len) % align
    need = (align - r) % align
    if need == 0:
        return b""
    if need < 4:
        need += align
    return struct.pack("<HH", 0xD935, need - 4) + b"\x00" * (need - 4)


def _entry_alignment(rawf, info, name_len):
    """Infer the alignment the original APK used for this entry."""
    if info.compress_type != zipfile.ZIP_STORED:
        return 0
    nlen, elen = _local_header(rawf, info)
    orig_data_off = info.header_offset + 30 + nlen + elen
    for align in (16384, 4096, 4):
        if orig_data_off % align == 0:
            return align
    return 4


def write_patched_apk(src_apk, out_path, patched_manifest, compress_so=False):
    """Rebuild the APK: every entry is re-written with the same compression,
    STORED entries keep their original zipalign padding (4 / 4096 / 16 KiB),
    only AndroidManifest.xml is replaced and stale v1 signature files are
    dropped. With compress_so=True (extractNativeLibs=true) the native
    libraries are deflated instead, which shrinks the APK and removes all
    alignment requirements on the device."""
    kept = replaced = dropped = 0
    with zipfile.ZipFile(src_apk, "r") as zin, \
            zipfile.ZipFile(out_path, "w") as zout, \
            open(src_apk, "rb") as rawf:
        for info in zin.infolist():
            name = info.filename
            # drop stale v1 signature files and the Play SourceStamp (its cert
            # belongs to the original app key and is invalid for our re-sign)
            if SIG_FILE_RE.match(name) or name == "stamp-cert-sha256":
                dropped += 1
                continue
            if name == "AndroidManifest.xml":
                data = patched_manifest
                method = zipfile.ZIP_DEFLATED
                replaced += 1
            else:
                with zin.open(info) as f:
                    data = f.read()
                if compress_so and name.endswith(".so"):
                    method = zipfile.ZIP_DEFLATED
                else:
                    method = (zipfile.ZIP_STORED
                              if info.compress_type == zipfile.ZIP_STORED
                              else zipfile.ZIP_DEFLATED)
                kept += 1
            try:
                name_bytes = name.encode("ascii")
            except UnicodeEncodeError:
                name_bytes = name.encode("utf-8")
            offset = zout.fp.tell()
            zi = zipfile.ZipInfo(name, date_time=info.date_time)
            zi.compress_type = method
            zi.external_attr = info.external_attr
            zi.internal_attr = info.internal_attr
            zi.create_system = info.create_system
            if method == zipfile.ZIP_STORED:
                align = _entry_alignment(rawf, info, len(name_bytes))
                if align:
                    zi.extra = _align_extra(offset, len(name_bytes), align)
            zout.writestr(zi, data)
        zout.comment = b""
    return kept, replaced, dropped


def find_tool(name):
    """Find a build-tools binary: prefer ANDROID_HOME, then common SDK paths."""
    exe = name + (".exe" if os.name == "nt" else "")
    home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    roots = []
    if home:
        roots.append(home)
    roots += [os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"),
              os.path.expanduser("~/Library/Android/sdk"),
              os.path.expanduser("~/Android/Sdk"), "/usr/local/lib/android/sdk"]
    bt = []
    for root in roots:
        bt += glob.glob(os.path.join(root, "build-tools", "*"))
    for d in sorted(bt, reverse=True):
        p = os.path.join(d, exe)
        if os.path.isfile(p):
            return p
        p2 = os.path.join(d, name + ".bat" if os.name == "nt" else name)
        if os.path.isfile(p2):
            return p2
    found = shutil.which(name)
    if found:
        return found
    return name  # last resort: hope it is on PATH


APKSIGNER = find_tool("apksigner")
KEYTOOL = find_tool("keytool")


def ensure_keystore(keystore, store_pass, alias, key_pass, dname):
    """Create the signing keystore if it does not exist yet."""
    if os.path.isfile(keystore):
        return False
    cmd = [KEYTOOL, "-genkeypair", "-v",
           "-keystore", keystore, "-storetype", "PKCS12",
           "-alias", alias, "-keyalg", "RSA", "-keysize", "2048",
           "-validity", "10000", "-storepass", store_pass,
           "-keypass", key_pass, "-dname", dname]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
    return True


def sign_apk(apk_path, keystore, store_pass, alias, key_pass):
    """Sign in place with apksigner using v1 + v2 + v3 schemes for maximum
    installer compatibility (some OEM installers are picky about schemes)."""
    cmd = [APKSIGNER, "sign",
           "--ks", keystore, "--ks-key-alias", alias,
           "--ks-pass", "pass:" + store_pass,
           "--key-pass", "pass:" + key_pass,
           "--min-sdk-version", "21",
           "--v1-signing-enabled", "true",
           "--v2-signing-enabled", "true",
           "--v3-signing-enabled", "true",
           apk_path]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)


def verify_apk(apk_path):
    res = subprocess.run([APKSIGNER, "verify", "--print-certs", apk_path],
                         capture_output=True, text=True)
    return res.returncode == 0, (res.stdout + res.stderr).strip()


def attr_map(strings, raw):
    """Map attribute keys -> parsed attribute for one start-element chunk."""
    out = {}
    for a in parse_attributes(raw):
        aname = strings[a["name"]] if a["name"] < len(strings) else "?"
        if a["ns"] != NO_INDEX and a["ns"] < len(strings) and strings[a["ns"]] == ANDROID_NS:
            key = "android:" + aname
        else:
            key = aname
        out[key] = a
    return out


def typed_value(strings, a):
    t, d = a["dtype"], a["data"]
    if t == TYPE_STRING:
        return strings[d] if d < len(strings) else "<bad string index>"
    if t == 0x10:  # INT
        return str(d - (1 << 32) if d >= 0x80000000 else d)
    if t == 0x11:  # HEX
        return "0x%x" % d
    if t == 0x12:  # BOOLEAN
        return "true" if d else "false"
    if t == TYPE_REFERENCE:
        return "@0x%08x" % d
    return "type=0x%02x data=0x%08x" % (t, d)


def dump_info(apk):
    """Print everything the cloner needs to know about the source APK."""
    with zipfile.ZipFile(apk) as z:
        manifest = z.read("AndroidManifest.xml")
        infos = z.infolist()
        meta = sorted(i.filename for i in infos if i.filename.startswith("META-INF/"))
        stored_so = [i for i in infos
                     if i.filename.endswith(".so") and i.compress_type == zipfile.ZIP_STORED]
        arsc = next((i for i in infos if i.filename == "resources.arsc"), None)
        total = sum(i.file_size for i in infos)
    strings, utf8, chunks = split_chunks(manifest)
    root = uses_sdk = None
    app_label = None
    providers = []
    label_count = 0
    for t, c in chunks:
        if t != RES_XML_START_ELEMENT_TYPE:
            continue
        raw = bytes(c)
        tag = _element_tag(strings, raw)
        attrs = attr_map(strings, raw)
        if tag == "manifest" and root is None:
            root = attrs
        elif tag == "uses-sdk" and uses_sdk is None:
            uses_sdk = attrs
        elif tag == "application" and app_label is None:
            app_label = attrs.get("android:label")
        elif tag == "provider":
            providers.append((
                typed_value(strings, attrs["android:name"]) if "android:name" in attrs else "?",
                typed_value(strings, attrs["android:authorities"]) if "android:authorities" in attrs else "?"))
        if "android:label" in attrs:
            label_count += 1
    if root is None:
        raise ValueError("no <manifest> element found")

    apk_size = Path(apk).stat().st_size
    print("Source APK     : %s (%.1f MB, %d zip entries)" % (apk, apk_size / 1e6, len(infos)))
    print("  package      : %s  versionName=%s versionCode=%s" % (
        typed_value(strings, root["package"]),
        typed_value(strings, root["android:versionName"]) if "android:versionName" in root else "?",
        typed_value(strings, root["android:versionCode"]) if "android:versionCode" in root else "?"))
    if uses_sdk:
        print("  sdk          : min=%s target=%s" % (
            typed_value(strings, uses_sdk["android:minSdkVersion"])
            if "android:minSdkVersion" in uses_sdk else "?",
            typed_value(strings, uses_sdk["android:targetSdkVersion"])
            if "android:targetSdkVersion" in uses_sdk else "?"))
    if app_label is not None:
        print("  app label    : %s" % typed_value(strings, app_label))
    print("  label attrs  : %d (every one will be replaced by the clone name)" % label_count)
    print("  providers    : %d (authorities will be re-prefixed with the new package)" % len(providers))
    for pname, auth in providers:
        print("    - %s [%s]" % (pname, auth))
    print("  string pool  : %d strings, %s encoding" % (len(strings), "UTF-8" if utf8 else "UTF-16"))
    print("  native libs  : %d STORED (arm64-v8a)" % len(stored_so))
    if arsc is not None:
        print("  resources.arsc: %s, %.1f MB" % (
            "STORED" if arsc.compress_type == zipfile.ZIP_STORED else "DEFLATED",
            arsc.file_size / 1e6))
    print("  META-INF     : %s" % (", ".join(meta) if meta else "empty (v2/v3-signed APK)"))


def find_source_apk(explicit=None):
    if explicit:
        return Path(explicit)
    cands = [p for p in Path(".").glob("*.apk") if p.is_file()]
    if not cands:
        return None
    cands.sort(key=lambda p: (not p.name.lower().startswith("quetta"), p.name))
    return cands[0]


def sanitize_suffix(name):
    """Turn a clone name into a valid Java package segment (lowercased)."""
    s = re.sub(r"[^a-z0-9_]", "_", name.lower())
    s = re.sub(r"_+", "_", s).strip("_") or "clone"
    if not re.match(r"^[a-z]", s):
        s = "app" + s
    return s


def load_names(path):
    names, seen = [], set()
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        n = line.strip()
        if n and n not in seen:
            seen.add(n)
            names.append(n)
    return names


def safe_filename(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def manifest_has_launcher(manifest):
    """True if the manifest declares an activity intent-filter with
    action MAIN + category LAUNCHER (i.e. the app has an icon to launch)."""
    strings, _utf8, chunks = split_chunks(manifest)
    has_main = has_launcher = False
    for t, c in chunks:
        if t != RES_XML_START_ELEMENT_TYPE:
            continue
        if _element_tag(strings, bytes(c)) in ("action", "category"):
            for a in parse_attributes(bytes(c)):
                if (a["ns"] != NO_INDEX and a["ns"] < len(strings)
                        and strings[a["ns"]] == ANDROID_NS
                        and strings[a["name"]] == "name" and a["dtype"] == TYPE_STRING):
                    v = strings[a["data"]]
                    if v == "android.intent.action.MAIN":
                        has_main = True
                    elif v == "android.intent.category.LAUNCHER":
                        has_launcher = True
    return has_main and has_launcher


def resolve_source(apk_path, splits_arg):
    """Return (base_apk, [split_apks], tmp_dir_or_None).

    Supports: a single standalone APK, a base APK plus a splits directory,
    or an .apks/.xapk bundle (zip of base + splits).
    """
    apk_path = Path(apk_path)
    if apk_path.suffix.lower() in (".xapk", ".apks", ".apkm", ".zip"):
        tmp = Path(tempfile.mkdtemp(prefix="apkset_"))
        with zipfile.ZipFile(apk_path) as z:
            z.extractall(tmp)
        apks = sorted(tmp.rglob("*.apk"))
        if not apks:
            sys.exit("no .apk files found inside %s" % apk_path)
        base = next((p for p in apks if p.name.lower() in ("base.apk", "base-master.apk")), apks[0])
        return base, [p for p in apks if p != base], tmp
    splits = []
    if splits_arg:
        sd = Path(splits_arg)
        if sd.is_dir():
            splits = sorted(p for p in sd.glob("*.apk")
                            if p.resolve() != apk_path.resolve())
        elif sd.is_file():
            splits = [sd]
        else:
            sys.exit("splits path not found: %s" % splits_arg)
    else:
        default_dir = apk_path.parent / "splits"
        if default_dir.is_dir():
            splits = sorted(p for p in default_dir.glob("*.apk")
                            if p.resolve() != apk_path.resolve())
    return apk_path, splits, None


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Batch APK cloner: rename package + app label, re-sign.")
    ap.add_argument("--apk", help="source APK / .apks / .xapk (default: auto-detect an *.apk in the current dir)")
    ap.add_argument("--splits", help="directory (or single file) with the split APKs that belong to the base APK")
    ap.add_argument("--names-file", default="names.txt")
    ap.add_argument("--only", help="comma-separated subset of clone names (overrides --count)")
    ap.add_argument("--count", type=int, default=0, help="only build the first N names from the file")
    ap.add_argument("--out", default="dist", help="output directory (default: dist)")
    ap.add_argument("--keystore", default="keystore/clone.keystore")
    ap.add_argument("--ks-pass", default="android")
    ap.add_argument("--ks-alias", default="clonekey")
    ap.add_argument("--key-pass", default="android")
    ap.add_argument("--no-sign", action="store_true", help="skip apksigner signing (debug only)")
    ap.add_argument("--jobs", type=int, default=0,
                    help="parallel clones to build (default: auto, up to 4)")
    ap.add_argument("--info", action="store_true", help="print source APK info and exit")
    args = ap.parse_args(argv)

    apk = find_source_apk(args.apk)
    if apk is None or not apk.is_file():
        sys.exit("source APK not found - pass --apk path/to/Quetta.apk")
    if args.info:
        dump_info(apk)
        return

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
    tmp_dir = out_dir / "_tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(apk) as z:
        manifest = z.read("AndroidManifest.xml")

    # resolve a possible split-APK set (Play base + feature/config splits)
    base_apk, split_apks, tmp_extract = resolve_source(apk, args.splits)
    split_manifests = []
    for sp in split_apks:
        with zipfile.ZipFile(sp) as z:
            split_manifests.append((sp, z.read("AndroidManifest.xml")))

    if not manifest_has_launcher(manifest) and not split_apks:
        sys.exit(
            "\n!!! This APK is a Play-Store BASE APK without its splits - it cannot\n"
            "    work standalone: it has no launcher activity and no app code\n"
            "    (that is why phones say 'app not compatible').\n\n"
            "    Get the COMPLETE app, then either:\n"
            "      * put the split APKs (split_*.apk / config.*.apk) into a folder\n"
            "        named 'splits' next to the base APK and re-run, or\n"
            "      * pass a .apks/.xapk bundle with --apk, or\n"
            "      * pass the full standalone APK from the official site/mirror.\n"
            "    To pull the full set from a phone that has the app installed:\n"
            "      adb shell pm path <package>   then   adb pull <each path>")

    keystore = None
    if not args.no_sign:
        probe = subprocess.run([APKSIGNER, "--version"], capture_output=True)
        if probe.returncode != 0:
            sys.exit("apksigner is not usable - install Android SDK build-tools "
                     "or set ANDROID_HOME (stderr: %s)"
                     % probe.stderr.decode(errors="replace").strip())
        Path(args.keystore).parent.mkdir(parents=True, exist_ok=True)
        if ensure_keystore(args.keystore, args.ks_pass, args.ks_alias, args.key_pass,
                           "CN=APK Clone, OU=Clone, O=Clone, C=US"):
            print("generated new keystore: %s" % args.keystore)
        keystore = args.keystore

    print("source          : %s (%d split APK(s) attached)"
          % (base_apk, len(split_apks)))
    print("clones to build : %d -> %s" % (len(names), out_dir))
    print()

    lock = threading.Lock()

    def build_one(task):
        i, name = task
        try:
            patched, _old, new_pkg, n_labels, n_auth, extract_patched, n_meta, n_sattr = \
                patch_manifest(manifest, sanitize_suffix(name), name)
            stem = safe_filename(name)
            built_files = []

            unsigned = tmp_dir / (stem + "_base.unsigned.apk")
            write_patched_apk(base_apk, unsigned, patched, compress_so=extract_patched)
            note = "unsigned"
            if not args.no_sign:
                sign_apk(unsigned, keystore, args.ks_pass, args.ks_alias, args.key_pass)
                ok, msg = verify_apk(unsigned)
                if not ok:
                    raise RuntimeError("apksigner verify failed:\n" + msg)
                note = "signed+verified"
            built_files.append((unsigned, "base.apk" if split_apks else None))

            for si, (sp, sman) in enumerate(split_manifests):
                sp_patched, _o2, _n2, _l2, _a2, _e2, _m2, _s2 = \
                    patch_manifest(sman, sanitize_suffix(name), name)
                sp_unsigned = tmp_dir / ("%s_s%02d.unsigned.apk" % (stem, si))
                write_patched_apk(sp, sp_unsigned, sp_patched, compress_so=extract_patched)
                if not args.no_sign:
                    sign_apk(sp_unsigned, keystore, args.ks_pass, args.ks_alias, args.key_pass)
                    ok2, msg2 = verify_apk(sp_unsigned)
                    if not ok2:
                        raise RuntimeError("apksigner verify failed for %s:\n%s" % (sp.name, msg2))
                built_files.append((sp_unsigned, sp.name))

            if split_apks:
                out_path = out_dir / ("%s.apks" % stem)
                with zipfile.ZipFile(out_path, "w", zipfile.ZIP_STORED) as bundle:
                    for f, arc in built_files:
                        bundle.write(f, arcname=arc)
                kind = "bundle: base + %d split(s)" % len(split_apks)
            else:
                out_path = out_dir / ("%s.apk" % stem)
                if out_path.exists():
                    out_path.unlink()
                built_files[0][0].replace(out_path)
                kind = "standalone"

            line = ("[%2d/%d] %-24s pkg=%s  (%.1f MB, %s, %d label(s), %d authorit(ies), "
                    "%d play-marker(s)+%d split-attr(s) removed, %s)" % (
                i, len(names), name, new_pkg, out_path.stat().st_size / 1e6,
                kind, n_labels, n_auth, n_meta, n_sattr, note))
            return i, name, out_path, line, None
        except Exception as exc:
            return i, name, out_path, "", exc

    built = [None] * len(names)
    workers = args.jobs if args.jobs > 0 else max(1, min(4, (os.cpu_count() or 2)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for i, name, out_path, line, err in pool.map(build_one, enumerate(names, 1)):
            with lock:
                if err is None:
                    print(line)
                    built[i - 1] = out_path
                else:
                    print("[%2d/%d] %-24s FAILED: %s" % (i, len(names), name, err))

    for f in tmp_dir.iterdir():
        f.unlink()
    tmp_dir.rmdir()
    if tmp_extract:
        shutil.rmtree(tmp_extract, ignore_errors=True)

    failed = [n for n, b in zip(names, built) if b is None]
    if failed:
        sys.exit("\nfailed clones: " + ", ".join(failed))

    # write checksums so copied files can be verified on the phone
    sums_path = out_dir / "SHA256SUMS.txt"
    with sums_path.open("w", encoding="utf-8") as fh:
        for p in built:
            h = hashlib.sha256()
            with p.open("rb") as f:
                for block in iter(lambda: f.read(1 << 20), b""):
                    h.update(block)
            fh.write("%s  %s\n" % (h.hexdigest(), p.name))
    print("checksums       : %s" % sums_path)
    print("\nDone: %d clone(s) in %s (workers=%d)"
          % (len(built), out_dir, workers))


if __name__ == "__main__":
    main()