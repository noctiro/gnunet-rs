#!/bin/sh
# Run inside the VM as an ordinary user, from the repository root.
set -eu
export TMPDIR=/tmp CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export RUSTDOCFLAGS='-D warnings' PYTHONDONTWRITEBYTECODE=1
rustup-init -y --profile minimal --default-toolchain none
. "$HOME/.cargo/env"
# Cargo installs the toolchain selected by rust-toolchain.toml.
RUSTUP_TOOLCHAIN=$(python3 -c 'from pathlib import Path; import tomllib; print(tomllib.loads(Path("rust-toolchain.toml").read_text())["toolchain"]["channel"])')
export RUSTUP_TOOLCHAIN
rustc -vV | grep -Fx 'host: x86_64-unknown-freebsd'
python3 -B tools/check_tools.py
cargo xtask verify portable
cargo xtask verify test
