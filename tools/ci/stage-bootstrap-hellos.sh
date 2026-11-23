#!/usr/bin/env bash
# Stage explicitly selected HELLO files for all app SDKs.
set -euo pipefail
export LC_ALL=C

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

if [[ $# != 2 || ! -d "$1" || -e "$2" || -L "$2" ]]; then
    fail "usage: stage-bootstrap-hellos.sh SOURCE_DIRECTORY NEW_GNUNET_DIRECTORY"
fi

source_dir=$(cd -- "$1" && pwd -P)
output_parent=$(cd -- "$(dirname -- "$2")" && pwd -P)
output_dir="$output_parent/$(basename -- "$2")"
stage=$(mktemp -d "$output_parent/.gnunet-hellos.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
mkdir "$stage/hellos"
: > "$stage/hellos.list"

shopt -s nullglob
count=0
total=0
for source_file in "$source_dir"/*; do
    [[ -f "$source_file" && ! -L "$source_file" ]] || fail "Expected a regular HELLO file at $source_file"
    (( count < 1024 )) || fail "Too many included HELLO files"
    printf -v name '%04d.hello' "$count"
    staged_file="$stage/hellos/$name"
    head -c 65536 < "$source_file" > "$staged_file"
    bytes=$(wc -c < "$staged_file")
    (( bytes > 0 && bytes <= 65535 )) || fail "Invalid included HELLO size at $source_file"
    (( total + bytes <= 4 * 1024 * 1024 )) || fail "Included HELLOs exceed 4 MiB"
    [[ $(head -c 15 < "$staged_file") == 'gnunet://hello/' ]] || fail "Expected a GNUnet HELLO URL at $source_file"
    printf '%s\n' "$name" >> "$stage/hellos.list"
    count=$((count + 1))
    total=$((total + bytes))
done
(( count > 0 )) || fail "The included HELLO directory is empty"
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || fail "The GNUnet output directory already exists"
mv -- "$stage" "$output_dir"
