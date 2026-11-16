#!/bin/sh
# Run inside the VM as an ordinary user, from the repository root.
set -eu
export TMPDIR=/tmp CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export RUSTDOCFLAGS='-D warnings' PYTHONDONTWRITEBYTECODE=1 PYTHONOPTIMIZE=
rustup-init -y --profile minimal --default-toolchain none
. "$HOME/.cargo/env"
# Repository selection must include the manifest's components, not just its channel.
unset RUSTUP_TOOLCHAIN
EXPECTED_RUST_HOST=x86_64-unknown-freebsd sh tools/ci/setup-rust.sh
git ls-files -z -- Cargo.lock '**/Cargo.lock' | xargs -0 -n 1 sh -ec 'cargo fetch --locked --manifest-path "${1%Cargo.lock}Cargo.toml"' sh
python3 -B tools/check_tools.py
cargo xtask verify native --log-dir target/ci/native
