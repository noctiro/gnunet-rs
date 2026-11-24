#!/bin/sh
# Run inside the VM as an ordinary user, from the repository root.
set -eu
# Bound concurrent rustc and linker memory inside the native test VM.
export TMPDIR=/tmp CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export RUSTDOCFLAGS='-D warnings' PYTHONDONTWRITEBYTECODE=1 PYTHONOPTIMIZE=
rustup-init -y --profile minimal --default-toolchain none
. "$HOME/.cargo/env"
# Repository selection must include the manifest's components, not just its channel.
unset RUSTUP_TOOLCHAIN
EXPECTED_RUST_HOST=x86_64-unknown-freebsd sh tools/ci/setup-rust.sh
# Keep native snapshot context with the copied test diagnostics. Probe failures
# remain visible without replacing the result of the actual workspace checks.
platform_probe() {
    printf '\n$'
    for probe_argument in "$@"; do
        printf ' %s' "$probe_argument"
    done
    printf '\n'
    if "$@"; then
        :
    else
        probe_status=$?
        printf 'probe exit status: %s\n' "$probe_status"
    fi
}
mkdir -p target/ci/native
{
    platform_probe uname -sr
    platform_probe freebsd-version -kru
    platform_probe id -u
    platform_probe pwd -P
    platform_probe df -T "$TMPDIR" .
    platform_probe mount -p
    platform_probe sysctl vfs.timestamp_precision
    platform_probe git rev-parse HEAD
    platform_probe git status --porcelain --untracked-files=no
    platform_probe rustc -Vv
} > target/ci/native/platform.log 2>&1
cat target/ci/native/platform.log
git ls-files -z -- Cargo.lock '**/Cargo.lock' | xargs -0 -n 1 sh -ec 'cargo fetch --locked --manifest-path "${1%Cargo.lock}Cargo.toml"' sh
python3 -B tools/check_tools.py
cargo xtask verify native --log-dir target/ci/native
