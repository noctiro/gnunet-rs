#!/bin/sh
# Provision a disposable CI host from rustup's complete repository manifest.
set -eu

cargo_bin="${CARGO_HOME:-$HOME/.cargo}/bin"
if command -v cygpath >/dev/null 2>&1; then
    cargo_bin=$(cygpath -u "$cargo_bin")
fi
export PATH="$cargo_bin:$PATH"
unset RUSTUP_TOOLCHAIN

if [ -n "${EXPECTED_RUST_HOST:-}" ]; then
    rustup set default-host "$EXPECTED_RUST_HOST"
fi
rustup toolchain install --no-self-update
active=$(rustup show active-toolchain)
RUSTUP_TOOLCHAIN=${active%% *}
export RUSTUP_TOOLCHAIN

version=$(rustc -vV)
printf '%s\n' "$version"
host=$(printf '%s\n' "$version" | sed -n 's/^host: //p')
if [ -n "${EXPECTED_RUST_HOST:-}" ] && [ "$host" != "$EXPECTED_RUST_HOST" ]; then
    printf 'expected native Rust host %s, got %s\n' "$EXPECTED_RUST_HOST" "$host" >&2
    exit 1
fi
if [ -n "${EXTRA_RUST_TARGETS:-}" ]; then
    printf '%s\n' "$EXTRA_RUST_TARGETS" | tr ',' ' ' | xargs rustup target add --
fi
cargo clippy --version
cargo fmt --version

if [ -n "${GITHUB_ENV:-}" ]; then
    printf 'RUSTUP_TOOLCHAIN=%s\n' "$RUSTUP_TOOLCHAIN" >> "$GITHUB_ENV"
fi
if [ -n "${GITHUB_PATH:-}" ]; then
    if command -v cygpath >/dev/null 2>&1; then
        cargo_bin=$(cygpath -w "$cargo_bin")
    fi
    printf '%s\n' "$cargo_bin" >> "$GITHUB_PATH"
fi
