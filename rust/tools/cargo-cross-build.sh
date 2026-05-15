#!/usr/bin/env bash
# Build host crates for the cross targets supported by the devcontainer.

set -euo pipefail

cd "$(dirname "$0")/.."

metadata="$(cargo metadata --no-deps --format-version 1)"
targets=(
    aarch64-apple-darwin
    x86_64-pc-windows-msvc
    aarch64-pc-windows-msvc
    aarch64-unknown-linux-musl
    x86_64-unknown-linux-musl
)

packages_for_target() {
    local target="$1"
    TARGET="$target" python3 -c '
import json
import os
import sys

metadata = json.load(sys.stdin)
target = os.environ["TARGET"]
prefixes = ("amla-vm-", "amla-ax-", "amla-container")

def has_cdylib_target(package):
    return any(
        "cdylib" in target.get("crate_types", [])
        for target in package["targets"]
    )

args = []
for package in metadata["packages"]:
    name = package["name"]
    if not name.startswith(prefixes):
        continue
    if target.endswith("-linux-musl") and has_cdylib_target(package):
        continue
    args.extend(("-p", name))

print(" ".join(args))
' <<< "$metadata"
}

for target in "${targets[@]}"; do
    echo "=== $target ==="
    pkg_args=$(packages_for_target "$target")
    read -ra packages <<< "$pkg_args"
    cargo build --all-targets --target "$target" "${packages[@]}"
done
