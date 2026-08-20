#!/system/bin/sh
# =============================================================================
# customize.sh - NM/ZM Conflict Scanner module entry point
# =============================================================================
# This is a SCAN-ONLY "module". It does NOT install anything.
#
# Behavior:
#   1. Refuses to run if flashed in custom recovery (BOOTMODE != true).
#   2. Detects Magisk vs KernelSU environment.
#   3. Sources $MODPATH/nm-scan.sh and runs the scanner against /data/adb/modules.
#   4. Prints results via ui_print (works in both manager UI and recovery console).
#   5. Calls abort() at the end so no stub module is left behind.
#
# This file is SOURCED (not executed) by the module installer. It runs in
# BusyBox ash with Standalone Mode enabled (per KernelSU docs). No bashisms.
# =============================================================================

# Do NOT skip unzip — we need $MODPATH/nm-scan.sh to be extracted first so we
# can source it. After scan, we abort() to trigger MODPATH cleanup.

# ---------------------------------------------------------------------------
# Recovery guard
# ---------------------------------------------------------------------------
# Per KernelSU docs: BOOTMODE is always true in KernelSU. KernelSU doesn't
# support recovery flashing at all, so this check is a no-op for KSU.
# Per Magisk: BOOTMODE=true when running in Magisk Manager (booted), false
# when running in custom recovery (TWRP/OrangeFox/etc.).
if [ "$BOOTMODE" != "true" ]; then
    ui_print "********************************************************"
    ui_print " [X] RECOVERY FLASHING NOT SUPPORTED"
    ui_print ""
    ui_print " This module must be flashed while the device is fully"
    ui_print " booted, using the Magisk or KernelSU manager app."
    ui_print ""
    ui_print " Custom recovery environments (TWRP, OrangeFox, etc.) do"
    ui_print " not have a populated /data/adb/modules directory, so"
    ui_print " the scan would produce garbage results."
    ui_print "********************************************************"
    abort "Recovery flashing is not supported. Flash in Magisk/KSU manager."
fi

# Belt-and-suspenders: MODPATH must be set by the installer
if [ -z "${MODPATH:-}" ]; then
    ui_print "[X] MODPATH not set. Aborting."
    abort "MODPATH not set by installer."
fi

# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------
# Per docs: KSU env var is "true" in KernelSU. MAGISK_VER_CODE is set in both
# Magisk AND KSU (KSU fakes it as 25200), so we must check KSU first.
ENV_NAME="Unknown"
ENV_VER="unknown"
if [ "${KSU:-}" = "true" ]; then
    ENV_NAME="KernelSU"
    ENV_VER="${KSU_VER:-unknown}"
elif [ -n "${MAGISK_VER_CODE:-}" ]; then
    ENV_NAME="Magisk"
    ENV_VER="v${MAGISK_VER_CODE}"
fi

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
ui_print "********************************************************"
ui_print " NM/ZM Conflict Scanner"
ui_print "--------------------------------------------------------"
ui_print " Environment : $ENV_NAME $ENV_VER"
ui_print " API level   : ${API:-unknown}"
ui_print " Architecture: ${ARCH:-unknown}"
ui_print " Modules dir : /data/adb/modules"
ui_print "********************************************************"
ui_print ""

# ---------------------------------------------------------------------------
# Source scanner and run
# ---------------------------------------------------------------------------
if [ ! -f "$MODPATH/nm-scan.sh" ]; then
    ui_print "[X] Scanner script not found: $MODPATH/nm-scan.sh"
    abort "Scanner script missing from module ZIP."
fi

# Source the scanner (defines nm_scan_main function)
. "$MODPATH/nm-scan.sh"

# Run the scan. nm_scan_main uses ui_print automatically (auto-detected).
# Pass /data/adb/modules as the target.
nm_scan_main "/data/adb/modules"
_scan_rc=$?

ui_print ""

# ---------------------------------------------------------------------------
# Finalize
# ---------------------------------------------------------------------------
case "$_scan_rc" in
    0)
        ui_print "********************************************************"
        ui_print " [+] SCAN COMPLETE: no conflicts found."
        ui_print " Your modules appear NM/ZM-friendly."
        ui_print "********************************************************"
        ;;
    2)
        ui_print "********************************************************"
        ui_print " [!] SCAN COMPLETE: conflicts found above."
        ui_print " Review the flagged lines before migrating to NM/ZM."
        ui_print "********************************************************"
        ;;
    *)
        ui_print "********************************************************"
        ui_print " [X] SCAN FAILED with code $_scan_rc."
        ui_print " Check the log above for errors."
        ui_print "********************************************************"
        ;;
esac

ui_print ""
ui_print "This is a SCAN-ONLY module. Nothing was installed."
ui_print "The installer will now abort to avoid leaving a stub"
ui_print "module behind in /data/adb/modules/."
ui_print ""

# Abort cleanly. The installer will print our message and clean up $MODPATH.
abort "Scan-only module - nothing to install. Use the log above."
