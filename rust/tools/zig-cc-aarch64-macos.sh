#!/bin/sh
# Wrapper so cc-rs can compile C code for aarch64-macos.
# On native macOS, use the system compiler. On other hosts, use zig as
# a cross-compiler and strip flags that zig handles via its own -target flag.
uname_s=$(uname -s)
if [ "$uname_s" = "Darwin" ]; then
    exec cc "$@"
fi

# Drop flags zig handles via its own -target flag while preserving the
# quoting of every other argument. Rebuilding $@ in place is the standard
# POSIX way to filter positional parameters without word-splitting.
saved_argc=$#
i=0
while [ $i -lt "$saved_argc" ]; do
    arg=$1
    shift
    i=$((i + 1))
    case "$arg" in
        --target=*) ;;
        -mmacosx-version-min=*) ;;
        *) set -- "$@" "$arg" ;;
    esac
done
exec zig cc -target aarch64-macos "$@"
