#!/bin/sh
# Share the native SDK version and notice files across packaging front ends.
set -efu

repo=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
case "${1:-}:$#" in
    version:1)
        metadata=$(cargo metadata --offline --locked --no-deps --format-version 1 \
            --manifest-path "$repo/platform/sdk/Cargo.toml")
        printf '%s\n' "$metadata" | python3 -B -c '
import json
import re
import sys
from pathlib import Path

manifest = Path(sys.argv[1]).resolve()
packages = [p for p in json.load(sys.stdin)["packages"]
            if p["name"] == "gnunet-node-sdk" and Path(p["manifest_path"]) == manifest]
if len(packages) != 1 or not re.fullmatch(r"[0-9A-Za-z.+-]+", packages[0]["version"]):
    raise SystemExit("Expected one native SDK package with a Cargo version")
print(packages[0]["version"])
' "$repo/platform/sdk/Cargo.toml"
        ;;
    notices:*)
        [ "$#" -ge 3 ] || exit 2
        destination=$2
        case "$destination" in /*) ;; *) destination="$PWD/$destination" ;; esac
        shift 2
        count=$#
        while [ "$count" -gt 0 ]; do
            target=$1
            shift
            set -- "$@" --target "$target"
            count=$((count - 1))
        done
        cd "$repo"
        export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
        exec cargo xtask stage-sdk-licenses --output "$destination" "$@"
        ;;
    *)
        printf 'Usage: sh %s version | notices DESTINATION RUST_TARGET...\n' "$0" >&2
        exit 2 ;;
esac
