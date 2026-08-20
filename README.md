# nm-compat-scanner

A scan-only Magisk / KernelSU module that detects shell commands in installed modules which may conflict with **NoMount (NM)** and **ZeroMount (ZM)** — kernel-level VFS path redirection frameworks for rooted Android.

The scanner runs during module install (via `customize.sh`), prints results to the manager UI, then aborts so **no stub module is left behind** in `/data/adb/modules/`.

---

## Why this exists

NoMount and ZeroMount redirect file paths at the kernel's VFS layer instead of using traditional bind mounts. If a module's `post-fs-data.sh` or `service.sh` calls `mount --bind`, `chcon` on `/system/...`, `sed -i /system/...`, or `mount -o remount,rw /system`, it will **silently break** under NM/ZM — files appear unmodified, or the system fails to boot.

This scanner finds those patterns so you can fix them before migrating to NM/ZM.

## Patterns detected

| Severity | What it catches |
|---|---|
| **HIGH** | `mount --bind`, `mount -t overlay`, `mount -o remount,rw /system`, `mount -t tmpfs .../system`, `chcon` on system path, `sed -i` on system path |
| **MED** | Any `remount,rw`, `restorecon` on system path, `echo > /system/...`, `printf > /system/...`, `cp`/`mv`/`mkdir`/`rm`/`unlink` on system path |
| **LOW** | `touch`/`chmod`/`chown` on system path (won't apply under NM redirection) |
| **INFO** | Manual `nm add` / `zeromount add` calls (review — may conflict with ZeroMount's auto-scan) |

Smart path anchor: real `/system/...` paths are flagged, but `$MODDIR/system/...` staging paths (the correct way to do systemless modules) are not.

## Install

### From a Release ZIP

1. Download the latest `nm-scanner-module-v*.zip` from [Releases](../../releases)
2. Open your Magisk or KernelSU manager app
3. **Modules → Install from storage → select the ZIP**
4. Watch the install log — the scan output appears there
5. The install will end with `abort "Scan-only module - nothing to install."` — this is expected; the installer cleans up the temporary MODPATH

### Build from source

```sh
git clone https://github.com/chandr1000/nm-compat-scanner.git
cd nm-compat-scanner
cd module && zip -r ../nm-scanner-module.zip . && cd ..
```

Flash `nm-scanner-module.zip` via your manager app.

## Standalone usage (no flash)

You can also run the scanner directly from a root shell or Termux:

```sh
# As root (Magisk/KSU shell)
sh nm-scan.sh

# From Termux (needs root)
ROOT=1 sh nm-scan.sh

# Custom modules path
sh nm-scan.sh /sdcard/my_mods
```

Exit codes:
- `0` — no conflicts found
- `1` — usage error / preflight failed
- `2` — conflicts found (useful for CI hooks)

## Recovery flashing

This module **refuses to run in custom recovery** (TWRP, OrangeFox). It only runs when the device is fully booted, inside the Magisk/KSU manager app. This is enforced via the `BOOTMODE` variable check in `customize.sh`.

Reason: `/data/adb/modules` is not populated in recovery, so the scan would produce garbage results.

## How it works

```
customize.sh                <- entry point (sourced by installer)
  ├─ Recovery guard: BOOTMODE != true → abort
  ├─ Detect Magisk vs KernelSU env
  ├─ Source nm-scan.sh
  └─ Run nm_scan_main /data/adb/modules → print results → abort

nm-scan.sh                  <- scanner logic (also usable standalone)
  ├─ Auto-detects ui_print (sourced mode) vs printf (standalone mode)
  ├─ 18 POSIX-ERE patterns, ~-delimited (not |, which would clash with ERE)
  ├─ Path anchor: matches real /system/... but skips $MODDIR/system/...
  └─ Line numbers via grep -nE

module/META-INF/...         <- standard Magisk installer stub (KSU ignores)
```

## Adding new patterns

Edit `nm-scan.sh` and append a line to the `_nm_patterns()` heredoc:

```
<id>~<severity>~<POSIX ERE>~<description>
```

- **Field separator**: `~` (tilde) — NOT `|`, because POSIX ERE uses `|` for alternation inside the regex
- **severity**: `HIGH` | `MED` | `LOW` | `INFO`
- The regex is fed directly to `grep -nE`

## Compatibility

- **Pure POSIX sh** — verified with `dash`
- Runs in Magisk's `ash` and KernelSU's `ash` (BusyBox Standalone Mode)
- Required utilities: `find`, `grep -nE`, `sed`, `wc`, `mktemp` (with fallback)

## Development

### Test workflow

GitHub Actions runs the scanner against synthetic fixtures on every push/PR to `main`. See [`.github/workflows/test.yml`](.github/workflows/test.yml).

### Release workflow

Push a tag matching `v*` to trigger the release build. The workflow:
1. Packages `module/` into a ZIP
2. Creates a GitHub Release attached to the tag
3. Uploads the ZIP as a release asset

```sh
git tag v1.0
git push origin v1.0
```

## License

GPL-3.0 — see [LICENSE](LICENSE).

## Credits

- [NoMount](https://github.com/maxsteeel/nomount) by maxsteeel — kernel-based file injection framework
- [ZeroMount](https://github.com/Enginex0/zeromount) by Enginex0 — mount orchestration engine for rooted Android
- [Magisk](https://github.com/topjohnwu/Magisk) by topjohnwu — the root solution
- [KernelSU](https://github.com/tiann/KernelSU) by tiann — kernel-based root solution
