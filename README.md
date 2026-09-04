# Quetta APK Batch Cloner

Turns one source APK (`Quetta.apk`, package `net.quetta.browser`) into one
installable clone per line of `names.txt` (37 names). Every clone:

| What | Value |
|---|---|
| Application/package id | `net.quetta.browser.<lowercased name>` |
| Launcher/app name | the name exactly as written in `names.txt` |
| Provider authorities | re-prefixed with the new package |
| Permission names | re-prefixed (declarations + references) |
| Signature | re-signed (v2/v3) with per-clone persistent keystore |
| Build.* fields | **spoofed per clone** (MODEL, MANUFACTURER, BRAND, FINGERPRINT, etc.) |
| V8 snapshots | preserved (32-bit + 64-bit) for Chromium renderer |
| Output | single standalone `.apk` (no SAI needed) |

Because each clone has a unique package id **and** unique provider authorities,
all clones install side by side with the original app.

## ⚠️ READ FIRST: your Quetta.xapk MUST include the arm64 V8 snapshot

The cloner merges all splits into a single standalone APK. But Quetta's V8
JavaScript engine requires two snapshot files:
  - `assets/snapshot_blob_32.bin` (32-bit V8 snapshot — present in the base APK)
  - `assets/snapshot_blob_64.bin` (64-bit V8 snapshot — in `config.arm64_v8a.apk`)

If your source `.xapk`/`.apks` was exported from a phone via SAI and is missing
the `config.arm64_v8a` split, the clones will launch but crash with
`[FATAL:gin/v8_initializer.cc:654] Error loading V8 startup snapshot file`
when you try to open any webpage ("Aw Snap").

**How to get a complete xapk:**
1. On the phone that has Quetta installed from Play Store, run:
   `adb shell pm path net.quetta.browser`
2. This lists ALL split APK paths. You need **every** one, especially
   `config.arm64_v8a.apk` (contains the 64-bit V8 snapshot).
3. `adb pull` each path, then zip them all into a `.xapk`:
   `zip Quetta_complete.xapk base.apk chrome.apk on_demand.apk config.*.apk`
4. Upload `Quetta_complete.xapk` to the `apk-source` release (replace existing).
5. Re-run the workflow.

**Quick check**: unzip your `.xapk` and look for `snapshot_blob_64.bin` inside
any of the APKs. If it's missing, you need to re-export with the config split.

---

## ⚠️ Previous note: your Quetta.apk is a Play *base* APK, not the full app

The `Quetta.apk` in this project was pulled from the Play Store and contains
**only the base module**. We proved this on a real emulator: installing it —
original **or** clone — fails with

```
INSTALL_FAILED_MISSING_SPLIT: Missing split for net.quetta.browser
```

which phones display as *"app not compatible with your phone"*. The actual
browser code and its launcher activity live in the **feature splits**
(`chrome__module` etc.) that were never part of this file.

**You need the complete set** (base + all splits). Pick one:

1. **From a phone that has Quetta installed from Play**: install the free
   **SAI (Split APKs Installer)** app → open SAI → *Install/Export* → export
   Quetta → you get `base.apk` + `split_*.apk` + `config.*.apk`.
2. **With adb**: `adb shell pm path net.quetta.browser` → `adb pull` every
   listed path.
3. **From an APK mirror** that ships the `.xapk`/`.apks` bundle.
4. **From the official site** — only if they distribute a real standalone APK.

Then either put the extra APKs in a `splits/` folder next to `Quetta.apk`,
or pass a `.apks`/`.xapk` bundle directly with `--apk`. The cloner detects
the mode automatically:

- **Standalone source** → outputs `<Name>.apk` per clone (direct install).
- **Base + splits** → outputs `<Name>.apks` per clone — transfer to the phone
  and install with the free **SAI** app (no adb needed), or
  `adb install-multiple base.apk split_*.apk ...`.

## Files

- `clone_apk.py` — the cloner (pure Python stdlib, no pip deps)
- `names.txt` — one clone name per line (source of truth for local + CI)
- `.github/workflows/build-clones.yml` — GitHub Actions workflow (37 parallel jobs)

## Local usage

```powershell
# inspect the source APK
python clone_apk.py --info

# first 4 names from names.txt
python clone_apk.py --apk Quetta.apk --count 4 --out dist

# specific names
python clone_apk.py --apk Quetta.apk --only "zetalite,Tovicrawlie" --out dist

# all 37 names, 4 workers in parallel
python clone_apk.py --apk Quetta.apk --out dist --jobs 4

# split-set mode (base + splits folder, or an .apks/.xapk bundle as --apk)
python clone_apk.py --apk Quetta.apk --splits splits --out dist
python clone_apk.py --apk Quetta.xapk --out dist
```

Requires: Python 3.8+, a JDK (`keytool`), and Android build-tools (`apksigner`)
— found automatically via `ANDROID_HOME` / `%LOCALAPPDATA%\Android\Sdk`,
or pass `APKSIGNER`/`KEYTOOL`-style PATH binaries.

Every clone is verified with `apksigner verify` right after signing.
Independent check:

```powershell
aapt2 dump badging dist\zetalite.apk   # package: name='net.quetta.browser.zetalite' ... application-label:'zetalite'
zipalign -c 4 dist\zetalite.apk        # must exit 0
```

## GitHub Actions usage (one-time setup)

1. Push this folder to a GitHub repo (note: `Quetta.apk` is 240 MB — GitHub
   blocks files > 100 MB in git, so **do not commit the APK**).
2. Create a release named tag **`apk-source`** and upload `Quetta.apk` as the
   release asset (Releases → Draft a new release → attach the file).
   The workflow downloads it from there on every run.
3. Run the workflow: *Actions → Build APK clones → Run workflow*.
   Optional inputs: `only` (subset of names), `make_release`.

### What you get

- **37 separate artifacts**, one per clone: `apk-zetalite`, `apk-Tovicrawlie`, …
  each artifact contains exactly its own single `.apk`.
- **37 raw `.apk` release assets** on release `clones-<run number>` — click any
  one to download the plain APK directly. (GitHub always wraps *artifact*
  downloads in a zip by platform design; release assets are the true
  no-zip, per-file download.)

### Signing keys — per-clone, persisted in the repo

Each clone gets its **own unique signing key**, stored at
`keystores/<name>.keystore` and **committed to the repo**. This means:

- **Updates work**: re-running the workflow produces clones signed with the
  *same key* as last time, so Android installs them as updates over the
  previous version (not as separate apps).
- **Per-clone isolation**: if one clone's key is ever compromised, only that
  one clone can be hijacked — the others are safe.
- **New names work automatically**: when you add a new name to `names.txt`,
  the next workflow run generates a keystore for it, commits it back to the
  repo, and uses it for all future builds of that clone.

The keystores live in `keystores/` (tracked by git). The keystore password is
`android` — this is a *signing identity*, not a secret. Anyone with the
keystore can sign "updates" to that clone, so don't share the repo publicly
if you care about that (or use a private repo).

**No GitHub secret setup needed** — the workflow handles keystore generation
and persistence automatically.

## Notes / limitations

- `resources.arsc` is not modified; the app name is set at manifest level
  (`android:label` → literal string), which is what the launcher displays.
- Clones set `android:extractNativeLibs=true` and compress the native libs:
  ~121 MB instead of 240 MB, and no page-size/alignment install requirements.
- `SHA256SUMS.txt` is written next to the clones — verify a copied file on the
  phone before installing (messaging-app transfers often corrupt 100 MB+ files).

## Updating clones when Quetta releases a new version

1. Download the new `Quetta.apk` (or `.xapk`) and re-upload it to the
   `apk-source` release (Releases → apk-source → edit → replace the asset).
2. Re-run the workflow (Actions → Build APK clones → Run workflow).
3. The workflow reuses each clone's existing keystore from `keystores/`, so
   every new build installs **over** the previous clone as a normal update.
4. If you added new names to `names.txt`, the workflow auto-generates
   keystores for them on this run and commits them.

## Adding new clone names

1. Edit `names.txt` — add one name per line at the end:
   ```
   ZetaLite
   ToviCrawlie
   NewName1
   NewName2
   ```
2. Commit and push (or just edit on GitHub's web UI).
3. Run the workflow (Actions → Build APK clones → Run workflow → Run).
4. The `prepare` job detects the new names, generates keystores for them,
   commits the keystores back to the repo, then builds all clones.
5. New clones appear in the next release.

## Device identity spoofing — what's implemented

### Build.* fields (NOW SPOOFED per clone) ✅

Every clone gets a **unique device profile** generated deterministically from
the clone name. The cloner patches all `Build.MODEL`, `Build.MANUFACTURER`,
`Build.BRAND`, `Build.DEVICE`, `Build.PRODUCT`, `Build.FINGERPRINT`,
`Build.DISPLAY`, `Build.HOST`, `Build.USER`, `Build.ID`, `Build.SERIAL`,
`Build.BOARD`, `Build.TAGS`, `Build.TYPE`, `Build.INCREMENTAL`,
`Build.VERSION.RELEASE`, `Build.VERSION.INCREMENTAL`,
`Build.VERSION.SECURITY_PATCH` references in the DEX code via smali patching.

This is the same technique AppCloner uses — every `sget-object` instruction
that reads a `Build.*` field is replaced with a `const-string` of the spoofed
value. The app reads the spoofed value instead of the real device info.

Example: clone "ZetaLite" might get a Sony XQ-CT72 profile, while clone
"AcxIrnoy" gets a Samsung SM-S921B profile. Each clone's device fingerprint
is unique and stable across reinstalls.

### What's already handled by the OS (no patching needed) ✅

| Identifier | How it's handled |
|---|---|
| `ANDROID_ID` | **Already unique per clone** — Android 8+ scopes it per app-signing-key. Each clone has its own keystore → automatically gets a unique ANDROID_ID. |
| Wi-Fi MAC | **Already randomized** — Android 6+ returns `02:00:00:00:00:00` to all apps. The OS handles this. |
| Bluetooth MAC | **Already randomized** — same as Wi-Fi MAC. |
| IMEI / MEID | **Already blocked** — Android 10+ returns `null` for all third-party apps (requires system-only `READ_PRIVILEGED_PHONE_STATE`). |
| SIM serial / IMSI / phone number | **Already blocked** — returns `null` for third-party apps since Android 10. |

### What CANNOT be spoofed (impossible without root) ❌

| Feature | Why | Workaround |
|---|---|---|
| **Play Integrity / SafetyNet** | Re-signed APKs fail `UNRECOGNIZED_VERSION`. Google also requires Play Store installation as of May 2025. | None — clones will always fail this. |
| **Banking apps** | Check Play Integrity | Won't work as clones |
| **Google Services (GMS)** | Check signature | Won't work as clones |
| **Real IMEI** (as seen by cell tower) | Hardware radio ID, OS-controlled | Only via LSPosed + root |
| **Real MAC** (as seen by Wi-Fi AP) | OS returns dummy since Android 6 | Already handled by OS |
| **Hardware-backed attestation** | Android 13+ proves bootloader is locked | Cannot be spoofed |

For full device spoofing (real IMEI, real MAC, Play Integrity bypass), you need
**LSPosed + root**. Install LSPosed and one of:
- **DeviceID Masker** — per-app IMEI / Android ID / MAC / Build profiles
- **XPrivacyLua** — comprehensive per-app identifier spoofing
- **Device Emulator Pro** — full device identity spoofing

## Clone safety

### Data isolation ✅

Each clone has a unique package name → unique UID → kernel-enforced sandbox.
The clone **cannot** read the original app's private data. The original app
**cannot** read the clone's data. This is enforced by the Linux kernel at the
UID level — same security boundary as any other app on Android.

### Keystore security ✅

Each clone has its **own unique signing key**, committed to the repo at
`keystores/<name>.keystore`. If one key is ever compromised, only that one
clone can be hijacked — the other 36 are safe. The keystore password is
`android` (not secret) — the keystore is a signing identity, not encryption.

**If you want maximum security**: make the repo **private** so only you can
access the keystores. Anyone with the keystore can sign "updates" to that clone.

### Network security ✅

Clones use the same network security config as the original app. HTTPS
certificate validation works the same way. No man-in-the-middle risk.

### Play Protect ⚠️

Google Play Protect sometimes flags re-signed apps as "unknown." To install:
1. Temporarily disable Play Protect during install
2. Or tap "Install anyway" when Play Protect warns
3. Play Protect will not remove the clone after installation

### What's NOT safe

- **Don't use clones for banking** — they fail Play Integrity
- **Don't use clones for Google Services** — they fail signature checks
- **Don't share your keystores publicly** — anyone can sign malicious "updates"

## If the phone says "app is not compatible"

1. **Is the source complete?** A Play base APK without its splits can never
   install — this was the actual cause for this project's `Quetta.apk`
   (proven on an emulator: the ORIGINAL fails the exact same way). See the
   section at the top of this file.
2. Check the file on the phone against `SHA256SUMS.txt` (any hash checker
   app) — corrupted transfers are the next most common cause.
3. Copy via USB cable (MTP) or download directly in the phone's browser —
   not via WhatsApp/Telegram (they alter files).
4. Temporarily disable Play Protect during install (it sometimes mislabels
   re-signed apps).
5. The app itself requires Android 12L/13+ and an arm64 phone (same as the
   original build) — your iQOO Neo 7 / iQOO Z3 both qualify.
