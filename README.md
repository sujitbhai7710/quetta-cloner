# Quetta APK Batch Cloner

Turns one source APK (`Quetta.apk`, package `net.quetta.browser`) into one
installable clone per line of `names.txt` (37 names). Every clone:

| What | Value |
|---|---|
| Application/package id | `net.quetta.browser.<lowercased name>` |
| Launcher/app name | the name exactly as written in `names.txt` |
| Provider authorities | re-prefixed with the new package (incl. multi-authority `;` lists) |
| Play distribution markers | removed (`splits.required`, stamp meta-data, `requiredSplitTypes`) |
| Signature | re-signed (v2/v3) with the project keystore |
| Everything else | untouched — binary-level patch, no decompile/recompile |

Because each clone has a unique package id **and** unique provider authorities,
all clones install side by side with the original app.

## ⚠️ READ FIRST: your Quetta.apk is a Play *base* APK, not the full app

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

## Device identity (IMEI / Android ID / SIM / MAC addresses) — HONEST version

**A cloned APK cannot change device identifiers by itself.** This is not a
limitation of this cloner — it's a fundamental Android security boundary.
Any tool that claims to spoof IMEI/MAC/etc. purely via APK patching is lying
to you; what they actually do is bundle an Xposed/LSPosed hook module
(which needs root) or use the in-process Java API hooks (which only affect
what the app *sees*, not what the OS/network/other apps see).

### What works WITHOUT root (already true for every clone)

| Identifier | Behavior |
|---|---|
| `Settings.Secure.ANDROID_ID` | Android 8+ automatically scopes this **per app-signing-key**. Since every clone is re-signed with a different keystore (or the same keystore but different package), each clone already gets a unique `ANDROID_ID` automatically. |
| Wi-Fi MAC (as seen by apps) | Android 10+ returns `02:00:00:00:00:00` to all apps by default. Apps cannot read the real hardware MAC. |
| Bluetooth MAC (as seen by apps) | Same — Android 6+ returns `02:00:00:00:00:00` to all apps. |
| `Build.MODEL`, `Build.MANUFACTURER`, etc. | These are read-only system properties. The app reads them via `Build.MODEL` etc., which the JIT often inlines at compile time. Reflection patching is unreliable on Android 9+. |

So out of the box, every clone already has:
- ✅ A unique `ANDROID_ID` (Android 8+)
- ✅ A randomized Wi-Fi MAC visible to the app (Android 10+)
- ✅ A randomized Bluetooth MAC visible to the app (Android 6+)
- ✅ A unique package id, so app-local data (SharedPreferences, databases) is per-clone

### What CANNOT be done via APK patching (requires LSPosed + root)

| Identifier | Why |
|---|---|
| Real IMEI / MEID / ESN | Hardware radio identifier. Apps with `READ_PRIVILEGED_PHONE_STATE` (system apps only since Android 11) read it directly from the modem. The OS doesn't expose a setter. |
| Real SIM serial / phone number / IMSI / carrier name | Read directly from the SIM card by the OS. No app API to override the return value without root hooks. |
| Real Wi-Fi MAC (as seen by access points) | Set by the Wi-Fi driver, not by Java. Apps can't touch it. |
| Real Bluetooth MAC (as seen by paired devices) | Set by the Bluetooth stack at the OS level. |

### How to spoof these (LSPosed module, rooted phones)

Install **LSPosed** (Zygisk edition is easiest) and one of these modules:

- **DeviceID Masker** — per-app IMEI / Android ID / MAC / Build fingerprint profiles
- **XPrivacyLua** — comprehensive per-app identifier spoofing
- **Device Emulator Pro** — full device identity spoofing (root required)

Enable the module for each clone package (`net.quetta.browser.zetalite`,
`net.quetta.browser.acxirnoy`, etc.), assign a different profile per clone,
and the spoofed values are returned to that clone only.

### Work profile (no root)

If you don't want to root, use **Island** or **Shelter** to run each clone
inside a separate work profile. Each work profile has its own `ANDROID_ID`
and its own app storage. Limitation: you can only have one work profile per
user, so this doesn't scale to 37 clones — but it works great for 1–3.

### Emulators (LDPlayer / MuMu / AVD)

Emulators let you change IMEI, Android ID, MAC, and build fingerprint per
instance from the emulator settings. Best option if you're running clones
on emulators rather than a real phone.

- The biggest web fingerprint after that is your **IP address** — use a
  different proxy/VPN exit per clone if the site tracks it.

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
