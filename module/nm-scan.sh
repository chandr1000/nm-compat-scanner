#!/system/bin/sh
# =============================================================================
# nm-scan.sh
# =============================================================================
# NoMount (NM) / ZeroMount (ZM) conflict scanner.
#
# Traverses a modules directory (default: /data/adb/modules) and detects shell
# scripts that contain commands which may conflict with NM/ZM kernel-level VFS
# path redirection.
#
# Designed to run in TWO contexts:
#   1. Sourced from a Magisk/KSU module's customize.sh (ui_print available).
#   2. Run directly from a shell/Termux (no ui_print; falls back to printf).
#
# Pure POSIX sh. No bashisms. No array. No [[ ]]. No local.
# Required utils: find, grep -nE, sed, wc, mktemp (or fallback to /tmp).
#
# Usage (standalone):
#   sh nm-scan.sh [modules_dir]
#
# Usage (from customize.sh):
#   . $MODPATH/nm-scan.sh
#   nm_scan_main "/data/adb/modules"
#
# Exit codes (standalone mode):
#   0  No conflicts
#   1  Usage error / preflight failed
#   2  Conflicts found
#
# Exit codes (sourced mode):
#   Does not exit; sets nm_scan_exit_code variable. Caller decides what to do.
# =============================================================================

# Default modules directory (can be overridden by $1 or NM_MODULES_DIR env)
_nm_default_dir="${NM_MODULES_DIR:-/data/adb/modules}"

# ---------------------------------------------------------------------------
# Output abstraction
# ---------------------------------------------------------------------------
# Auto-detect ui_print availability. The installer defines ui_print as a shell
# function before sourcing customize.sh. command -v detects both functions and
# builtins portably in POSIX sh.
if command -v ui_print >/dev/null 2>&1; then
    _NM_HAVE_UI_PRINT=1
    # ui_print typically expects a single line. Multi-line args may render
    # badly in some manager UIs, so we split on \n before calling ui_print.
    out() {
        # Use printf to split on newlines, then call ui_print per line
        # Use IFS= to preserve leading whitespace
        printf '%s\n' "$*" | while IFS= read -r _ln; do
            ui_print "$_ln"
        done
    }
else
    _NM_HAVE_UI_PRINT=0
    out() { printf '%s\n' "$*"; }
fi

# Severity markers (ASCII-only; no ANSI colors — manager UI doesn't render them)
_m_high() { out "[X] $*"; }   # HIGH: likely breaks NM/ZM
_m_med()  { out "[!] $*"; }   # MED:  review
_m_low()  { out "[-] $*"; }   # LOW:  info
_m_info() { out "[+] $*"; }   # INFO: ok / informational
_m_hdr()  { out "== $*"; }

# ---------------------------------------------------------------------------
# Ensure TMPDIR is writable (Android may not set it)
# ---------------------------------------------------------------------------
if [ -z "${TMPDIR:-}" ]; then
    if [ -d /data/local/tmp ] && [ -w /data/local/tmp ]; then
        TMPDIR=/data/local/tmp
    elif [ -d /tmp ] && [ -w /tmp ]; then
        TMPDIR=/tmp
    fi
    export TMPDIR
fi

# ---------------------------------------------------------------------------
# System partition names — SINGLE SOURCE OF TRUTH
# ---------------------------------------------------------------------------
# Used by both detection patterns and the false-positive filter.
# Only names listed here are treated as partition-mimicking module
# subdirectories.  Other dirs (e.g. x86 for zygisk, staging, etc.) are
# never stripped by the filter, so they won't produce false negatives.
#
# To add a new OEM-specific partition (e.g. mi_ext, oppo_ext), append it
# to the alternation below.  Both patterns and filter pick it up automatically.
# ---------------------------------------------------------------------------
_NM_SYS_PARTS='system|vendor|product|system_ext|odm|mi_ext'

# Shorthand: ERE fragment for a word-boundary before a partition path.
# Produces e.g. (^|[^[:alnum:]_/])/(system|vendor|...)/
# The inner parentheses around \$_NM_SYS_PARTS are CRITICAL — without them
# the ERE alternation would be unscoped and each partition name would
# match any line containing that word (ERE | has lowest precedence).
_nm_part_boundary="(^|[^[:alnum:]_/])/($_NM_SYS_PARTS)"

# ---------------------------------------------------------------------------
# Pattern definitions
# Format: <id>~<severity>~<POSIX ERE>~<description>
# Field separator is '~' (tilde) to avoid clashing with ERE '|'.
# severity: HIGH | MED | LOW | INFO
# ---------------------------------------------------------------------------
_nm_patterns() {
    # NOTE: heredoc uses EOF (not 'EOF') so $_NM_SYS_PARTS is expanded.
    # None of the pattern text contains literal dollar signs, so this is safe.
    cat <<EOF
mount_bind~HIGH~(^|[[:space:]])mount[[:space:]]+.*--bind~Bind-mount over a path NM/ZM may also redirect (competing redirection)
mount_overlay~HIGH~(^|[[:space:]])mount[[:space:]]+(-t[[:space:]]+)?overlay~OverlayFS mount - conflicts with NM/ZM VFS layer
mount_remount_rw_system~HIGH~mount.*remount.*rw.*$_nm_part_boundary($|[^[:alnum:]_/])~Force-remount system partition rw - will fail/panic on protected kernels
mount_remount_rw_generic~MED~mount.*-o.*remount.*rw~Any remount,rw attempt - review target
mount_tmpfs_system~HIGH~mount.*-t[[:space:]]+tmpfs.*$_nm_part_boundary/~tmpfs over system path - competes with VFS layer
chcon_system~HIGH~chcon[[:space:]].*$_nm_part_boundary/~chcon on a real system path - label won't reach NM-redirected inode; use staging dir
restorecon_system~MED~restorecon[[:space:]].*$_nm_part_boundary/~restorecon on system path - similar to chcon; prefer staging
sed_i_system~HIGH~sed[[:space:]]+.*-i.*$_nm_part_boundary/~sed -i on a live system path - breaks under NM (path is virtual, file is read-only)
echo_redirect_system~MED~echo[[:space:]].*>[[:space:]]*$_nm_part_boundary/~echo redirect to system path - won't persist under NM
printf_redirect_system~MED~printf[[:space:]].*>[[:space:]]*$_nm_part_boundary/~printf redirect to system path - won't persist under NM
cp_to_system~MED~(^|[[:space:]])cp[[:space:]].*$_nm_part_boundary/~cp targeting system path - should copy to module staging dir
mv_to_system~MED~(^|[[:space:]])mv[[:space:]].*$_nm_part_boundary/~mv targeting system path - should be done via module staging
mkdir_system~MED~(^|[[:space:]])mkdir[[:space:]].*$_nm_part_boundary/~mkdir on system path - should be done via module staging
rm_system~MED~(^|[[:space:]])(rm|unlink)[[:space:]].*$_nm_part_boundary/~rm/unlink on system path - read-only partition
touch_system~LOW~(^|[[:space:]])touch[[:space:]].*$_nm_part_boundary/~touch on system path - review
chmod_system~LOW~(^|[[:space:]])chmod[[:space:]].*$_nm_part_boundary/~chmod on system path - won't apply if NM is redirecting it
chown_system~LOW~(^|[[:space:]])chown[[:space:]].*$_nm_part_boundary/~chown on system path - won't apply if NM is redirecting it
nm_add_call~INFO~(^|[[:space:]])(nm|zeromount)[[:space:]]+add~Manual nm/zeromount add call - review whether it conflicts with ZeroMount's auto-scan
EOF
}

# ---------------------------------------------------------------------------
# False-positive filter for file-operation patterns.
# ---------------------------------------------------------------------------
# Per KernelSU/Magisk module convention, modules may place files under
# subdirectories named after system partitions (system/, vendor/,
# product/, system_ext/, odm/, mi_ext/, etc.) which OverlayFS later
# mounts onto the real partitions.  Operations on those paths are the
# CORRECT way to do systemless modifications and must NOT be flagged.
#
# IMPORTANT: only partition names listed in _NM_SYS_PARTS are treated as
# module-internal.  Non-partition dirs like x86 (zygisk), staging, etc.
# are never stripped — they cannot produce false negatives.
#
# Strategy: strip module-internal path references from each matched line,
# then keep only lines where a bare partition path still remains.
#
# This correctly handles lines with BOTH module-internal and real
# partition paths (e.g. cp /system/file $MODDIR/backup/) — the real
# /system/ ref survives stripping and the line is still flagged.
#
# Patterns that need this filter: file operations (cp, mv, mkdir, rm,
# touch, chmod, chown, chcon, restorecon, sed -i, echo>, printf>) where
# the partition path could be module-internal.
#
# Patterns that do NOT need this filter: mount operations (bind, overlay,
# remount, tmpfs) — these are inherently system-level and cannot be
# module-internal.
# ---------------------------------------------------------------------------
_nm_filter_safe_context() {
    # Strip paths where a partition name appears after a module directory
    # variable ($VAR/ ${VAR}/) or /data/adb/modules/<id>/.  Uses the same
    # _NM_SYS_PARTS list as the detection patterns for consistency.
    # Then keep only lines that still contain a bare partition path.
    sed -E \
        -e "s~\\\$[{]?[A-Za-z_][A-Za-z0-9_]*[}]?/($_NM_SYS_PARTS)/[^ \"[:space:]]*~~g" \
        -e "s~/data/adb/modules/[^/[:space:]]+/($_NM_SYS_PARTS)/[^ \"[:space:]]*~~g" \
    | grep -E "(^|[^[:alnum:]_/])/($_NM_SYS_PARTS)/"
}

# ---------------------------------------------------------------------------
# Main scanner function. Call with: nm_scan_main [modules_dir]
# Sets: nm_scan_exit_code (0=clean, 1=preflight error, 2=conflicts found)
# ---------------------------------------------------------------------------
nm_scan_main() {
    nm_scan_exit_code=0
    _modules_dir="${1:-$_nm_default_dir}"

    if [ ! -d "$_modules_dir" ]; then
        _m_high "Modules directory not found: $_modules_dir"
        nm_scan_exit_code=1
        return 1
    fi

    if ! command -v grep >/dev/null 2>&1; then
        _m_high "grep not found. Cannot scan."
        nm_scan_exit_code=1
        return 1
    fi
    if ! command -v find >/dev/null 2>&1; then
        _m_high "find not found. Cannot traverse modules dir."
        nm_scan_exit_code=1
        return 1
    fi

    # Probe grep -nE support once
    _have_grep_ne=0
    if printf 'x\n' | grep -nE 'x' >/dev/null 2>&1; then
        _have_grep_ne=1
    fi

    # Temp files
    _pattern_file=""
    _scripts_list=""
    _nm_cleanup() {
        [ -n "$_pattern_file" ] && [ -f "$_pattern_file" ] && rm -f "$_pattern_file"
        [ -n "$_scripts_list" ]  && [ -f "$_scripts_list" ]  && rm -f "$_scripts_list"
    }
    # Use trap only when running standalone (not sourced); when sourced by
    # customize.sh, the parent's trap will handle cleanup. We still set our own
    # trap on EXIT — it's safe to layer.
    trap _nm_cleanup EXIT INT HUP TERM

    if command -v mktemp >/dev/null 2>&1; then
        _pattern_file=$(mktemp 2>/dev/null)
        _scripts_list=$(mktemp 2>/dev/null)
    fi
    if [ -z "$_pattern_file" ] || [ ! -f "$_pattern_file" ]; then
        _pattern_file="${TMPDIR:-.}/nm_patterns.$$"
        : > "$_pattern_file" || { _m_high "Cannot create temp file: $_pattern_file"; nm_scan_exit_code=1; return 1; }
    fi
    if [ -z "$_scripts_list" ] || [ ! -f "$_scripts_list" ]; then
        _scripts_list="${TMPDIR:-.}/nm_scripts.$$"
        : > "$_scripts_list" || { _m_high "Cannot create temp file: $_scripts_list"; nm_scan_exit_code=1; return 1; }
    fi

    # Write patterns to file (so we can read it back with `while read`)
    _nm_patterns > "$_pattern_file"
    _pattern_count=$(wc -l < "$_pattern_file" | tr -d ' \t')

    # Discover script files
    _m_info "Modules dir : $_modules_dir"
    _m_info "Phase 1: discovering script files..."

    # Common Magisk/KSU module script names + any *.sh
    # Use -print0 if available? Not portable to toybox; use -print.
    find "$_modules_dir" -type f \( \
        -name "post-fs-data.sh"      -o \
        -name "service.sh"           -o \
        -name "uninstall.sh"         -o \
        -name "customize.sh"         -o \
        -name "action.sh"            -o \
        -name "boot-completed.sh"    -o \
        -name "post-mount.sh"        -o \
        -name "install.sh"           -o \
        -name "update-binary"        -o \
        -name "*.sh"                 \
    \) -print > "$_scripts_list" 2>/dev/null

    _total_scripts=$(wc -l < "$_scripts_list" | tr -d ' \t')
    _m_info "Discovered $_total_scripts script file(s)."
    _m_info "Phase 2: scanning with $_pattern_count patterns..."
    out ""
    if [ "$_have_grep_ne" = "0" ]; then
        _m_low "grep -n not supported on this shell - line numbers will be omitted."
    fi

    # Scan loop
    _conflict_count=0
    _files_with_conflicts=0

    while IFS= read -r _script; do
        [ -z "$_script" ] && continue
        [ -f "$_script" ] || continue

        _file_hit=0

        while IFS='~' read -r _pid _sev _regex _desc; do
            [ -z "$_pid" ] && continue
            case "$_pid" in '#'*) continue ;; esac

            _matches=""
            if [ "$_have_grep_ne" = "1" ]; then
                _matches=$(grep -nE -- "$_regex" "$_script" 2>/dev/null)
            else
                _matches=$(grep -E -- "$_regex" "$_script" 2>/dev/null | sed 's/^/?: /')
            fi

            # Filter false positives for file-operation patterns where the
            # system path may be module-internal ($MODDIR/system/... etc.)
            # instead of a real system path.  Mount patterns are excluded —
            # they are inherently system-level operations.
            if [ -n "$_matches" ]; then
                case "$_pid" in
                    chcon_system|restorecon_system|sed_i_system|echo_redirect_system|printf_redirect_system|cp_to_system|mv_to_system|mkdir_system|rm_system|touch_system|chmod_system|chown_system)
                        _matches=$(printf '%s\n' "$_matches" | _nm_filter_safe_context)
                        ;;
                esac
            fi

            if [ -n "$_matches" ]; then
                if [ "$_file_hit" = "0" ]; then
                    _m_hdr "File: $_script"
                    _file_hit=1
                    _files_with_conflicts=$((_files_with_conflicts + 1))
                fi
                # Severity prefix
                case "$_sev" in
                    HIGH) _m_high "[$_sev] $_desc" ;;
                    MED)  _m_med  "[$_sev] $_desc" ;;
                    LOW)  _m_low  "[$_sev] $_desc" ;;
                    INFO) _m_info "[$_sev] $_desc" ;;
                    *)    out     "[$_sev] $_desc" ;;
                esac
                # Print each matched line.
                # Use printf '%s\n' (not '%s') so the last line still gets a
                # trailing newline — without it, `read` would silently drop the
                # final match because $(...) strips trailing newlines.
                printf '%s\n' "$_matches" | while IFS= read -r _ml; do
                    out "       $_ml"
                done
                _conflict_count=$((_conflict_count + 1))
            fi
        done < "$_pattern_file"

        if [ "$_file_hit" = "1" ]; then
            out ""
        fi
    done < "$_scripts_list"

    # Summary
    out "============================================"
    out "Summary"
    out "  Modules dir scanned   : $_modules_dir"
    out "  Script files discovered: $_total_scripts"
    out "  Files with conflicts   : $_files_with_conflicts"
    out "  Total conflict matches : $_conflict_count"
    out "============================================"

    if [ "$_conflict_count" -gt 0 ]; then
        _m_med "Conflicts detected. Review flagged modules before enabling NoMount/ZeroMount."
        nm_scan_exit_code=2
    else
        _m_info "No conflict patterns detected. Modules look NM/ZM-friendly."
        nm_scan_exit_code=0
    fi

    _nm_cleanup
    return $nm_scan_exit_code
}

# ---------------------------------------------------------------------------
# When run directly (not sourced), execute nm_scan_main with $1 or default.
# When sourced, do nothing — caller invokes nm_scan_main explicitly.
# Detection: see if $0 ends with our filename. Sourced $0 is the parent shell.
# ---------------------------------------------------------------------------
_nm_is_sourced() {
    # Heuristic: if the function nm_scan_main is defined AND $0 doesn't look
    # like our filename, we were sourced.
    case "$0" in
        *nm-scan.sh) return 1 ;;  # direct execution
        *)           return 0 ;;  # sourced
    esac
}

# Only auto-run when executed directly (not sourced from customize.sh)
if ! _nm_is_sourced; then
    nm_scan_main "$1" "${2:-}"
    _rc=$?
    exit $_rc
fi
