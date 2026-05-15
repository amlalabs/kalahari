#!/usr/bin/env bash
# Linker wrapper: calls the linker, then codesigns the output
# if it contains a __DATA,__entitlements Mach-O section.
#
# For binaries with entitlements, this wrapper also strips debug info
# BEFORE codesigning (rustc's post-link strip would invalidate the
# signature). Pair with per-package `strip = "none"` for those crates.
# Binaries without entitlements are left alone for rustc to strip.
#
# Works on both macOS (native tools) and Linux (zig cc + llvm + rcodesign).
#
# Set in .cargo/config.toml:
#   [target.aarch64-apple-darwin]
#   linker = "tools/link-and-sign.sh"

set -euo pipefail

# Detect platform and pick tools accordingly.
uname_kernel=$(uname -s)
case "$uname_kernel" in
    Darwin)
        LINKER=(cc)
        OTOOL=(otool -l)
        STRIP=(strip -S)
        CODESIGN=(codesign --sign - --entitlements)
        ;;
    *)
        SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
        : "${ZIG_LOCAL_CACHE_DIR:=/tmp/zig-cache}"
        : "${ZIG_GLOBAL_CACHE_DIR:=/tmp/zig-cache}"
        export ZIG_LOCAL_CACHE_DIR ZIG_GLOBAL_CACHE_DIR
        mkdir -p "$ZIG_LOCAL_CACHE_DIR" "$ZIG_GLOBAL_CACHE_DIR"
        LINKER=(zig cc -target aarch64-macos "-F${SCRIPT_DIR}/macos-stubs")
        OTOOL=(llvm-objdump --macho --all-headers)
        STRIP=(llvm-strip -S)
        CODESIGN=(rcodesign sign --code-signature-flags runtime --entitlements-xml-path)
        ;;
esac

# On Linux, filter args that conflict with zig's linker:
#  --target=*                 — zig sets this via -target in $LINKER
#  -liconv                    — iconv is re-exported from libSystem
#  -exported_symbols_list ... — unsupported by zig's Darwin linker
uname_s=$(uname -s)
if [ "$uname_s" != "Darwin" ]; then
    filtered_args=()
    skip_next_export_list=0
    for arg in "$@"; do
        if [ "$skip_next_export_list" -eq 1 ]; then
            skip_next_export_list=0
            continue
        fi
        case "$arg" in
            --target=*|-mmacosx-version-min=*|-liconv) ;;
            -Wl,-exported_symbols_list|-exported_symbols_list)
                skip_next_export_list=1
                ;;
            -Wl,-exported_symbols_list,*|-Wl,-exported_symbols_list=*) ;;
            *) filtered_args+=("$arg") ;;
        esac
    done
    set -- "${filtered_args[@]}"
fi

# Invoke the linker.
"${LINKER[@]}" "$@"

# Find the output path from -o flag.
output=""
prev=""
for arg in "$@"; do
    if [ "$prev" = "-o" ]; then output="$arg"; break; fi
    prev="$arg"
done
[ -z "$output" ] && exit 0
[ -f "$output" ] || exit 0

# Check for __DATA,__entitlements section.
info=$("${OTOOL[@]}" "$output" 2>/dev/null | grep -A5 "sectname __entitlements" || true)
[ -z "$info" ] && exit 0

offset=$(echo "$info" | awk '/^[[:space:]]+offset/{print $2; exit}')
size=$(echo "$info" | awk '/^[[:space:]]+size/{print $2; exit}')
[ -z "$offset" ] || [ -z "$size" ] && exit 0

# Strip debug info before codesigning (rustc's post-link strip would
# invalidate the signature, so the crate must set strip = "none").
"${STRIP[@]}" "$output" 2>/dev/null || true

# Extract the entitlements plist and codesign.
tmp=$(mktemp "${TMPDIR:-/tmp}/entitlements.XXXXXX")
dd if="$output" bs=1 skip="$((offset))" count="$((size))" of="$tmp" 2>/dev/null
"${CODESIGN[@]}" "$tmp" --force "$output" 2>/dev/null || \
    "${CODESIGN[@]}" "$tmp" "$output" 2>/dev/null || true
rm -f "$tmp"
