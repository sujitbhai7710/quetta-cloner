# Quetta APK Batch Cloner

Turns one source APK (`Quetta.apk`, package `net.quetta.browser`) into one
installable clone per line of `names.txt` (37 names). Every clone:

| What | Value |
|---|---|
| Application/package id | `net.quetta.browser.<lowercased name>` |
| Launcher/app name | the name exactly as written in `names.txt` |
| Provider authorities | re-prefixed with the new package (incl. multi-authority `;` lists) |
| Signature | re-signed (v2/v3) with the project keystore |
| Everything else | untouched — binary-level patch, no decompile/recompile |

Because each clone has a unique package id **and** unique provider authorities,
all clones install side by side with the original app.

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

# all 37 names, 4 workers in parallel (~1 min)
python clone_apk.py --apk Quetta.apk --out dist --jobs 4
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

### Signing key across runs

By default each run generates a fresh keystore (clones from different runs
can't update each other). To reuse one key forever, base64 the local keystore
once and store it as the repo secret `CLONE_KEYSTORE_B64`:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("keystore\clone.keystore")) | Set-Clipboard
```

## Notes / limitations

- `resources.arsc` is not modified; the app name is set at manifest level
  (`android:label` → literal string), which is what the launcher displays.
- Clones set `android:extractNativeLibs=true` and compress the native libs:
  ~121 MB instead of 240 MB, and no page-size/alignment install requirements.
- `SHA256SUMS.txt` is written next to the clones — verify a copied file on the
  phone before installing (messaging-app transfers often corrupt 100 MB+ files).

## Updating clones when Quetta releases a new version

1. Download the new `Quetta.apk` and re-upload it to the `apk-source` release
   (Releases → apk-source → edit → replace the asset).
2. Re-run the workflow (or locally: `python clone_apk.py --apk QuettaNew.apk --out dist`).
3. Package ids come from `names.txt` and the signing key comes from
   `CLONE_KEYSTORE_B64` / `keystore/clone.keystore` — both unchanged — so each
   new build installs **over** the previous clone as a normal update.

## Device identity (IMEI / Android ID / SIM / MAC addresses)

A cloned APK **cannot** change these: IMEI, SIM serial/phone number, operator,
Wi-Fi/BT MAC and `Settings.Secure.ANDROID_ID` come from the operating system at
runtime, not from the APK. Randomizing them per clone has to happen on the
device. What works (per clone, because every clone has its own package id):

- **LSPosed module** (rooted phones): "Device Spoofing" / "Device ID Changer"
  style modules let you assign a different fake IMEI / Android ID / MAC /
  build fingerprint **per package** — one profile per clone.
- **Work profile / Island / Shelter**: runs a clone in a separate profile with
  a different Android ID, no root needed.
- **Emulators** (LDPlayer/MuMu/AVD): change device model, IMEI and Android ID
  per instance.
- The biggest web fingerprint after that is your **IP address** — use a
  different proxy/VPN exit per clone if the site tracks it.

## If the phone says "app is not compatible"

1. Check the file on the phone against `SHA256SUMS.txt` (any MD5/SHA checker
   app) — a corrupted 120–240 MB transfer is the most common cause.
2. Copy via USB cable (MTP), not via WhatsApp/Telegram (they alter files).
3. Temporarily disable Play Protect during install (it sometimes mislabels
   re-signed apps).
4. The clone requires Android 12L/13+ and an arm64 phone (same as the
   original Quetta build) — your iQOO Neo 7 / iQOO Z3 both qualify.
