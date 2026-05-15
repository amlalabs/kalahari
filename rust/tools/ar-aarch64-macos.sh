#!/bin/sh
# Archive tool wrapper for aarch64-macos C dependencies.
# Native macOS has /usr/bin/ar; cross builds use llvm-ar.
uname_s=$(uname -s)
if [ "$uname_s" = "Darwin" ]; then
    exec ar "$@"
fi

exec llvm-ar "$@"
