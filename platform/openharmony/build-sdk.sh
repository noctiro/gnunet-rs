#!/bin/sh
set -efu

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

repo=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
platform="$repo/platform/openharmony"
profiles="$platform/abis.tsv"

case "${1:-}" in
    --help|-h)
        printf 'Usage: OHOS_NATIVE=/path/to/native sh %s [ABI...]\n' "$0"
        printf 'Inspect available ABIs with --abis or their Rust targets with --rust-targets.\n'
        exit 0 ;;
    --abis)
        [ "$#" -eq 1 ] || fail 'Expected --abis without ABI arguments.'
        cut -f 1 "$profiles"
        exit ;;
    --rust-targets)
        [ "$#" -eq 1 ] || fail 'Expected --rust-targets without ABI arguments.'
        cut -f 2 "$profiles"
        exit 0 ;;
esac
if [ "$#" -eq 0 ]; then
    abis=$(cut -f 1 "$profiles")
    set -- $abis
fi

cd "$repo"
output="$repo/target/openharmony"
jobs=${GNUNET_OHOS_BUILD_JOBS:-1}
case "$jobs" in
    ''|*[!0-9]*) fail 'GNUNET_OHOS_BUILD_JOBS must be a positive integer.' ;;
esac
[ "$jobs" -ge 1 ] 2>/dev/null || fail 'GNUNET_OHOS_BUILD_JOBS must be a positive integer.'

case "$(uname -s)" in
    Linux|Darwin) ;;
    *) fail 'Use the OpenHarmony native SDK for a Linux or macOS host.' ;;
esac
: "${OHOS_NATIVE:?Set OHOS_NATIVE to the extracted OpenHarmony native SDK directory.}"
OHOS_NATIVE=$(CDPATH='' cd -- "$OHOS_NATIVE" && pwd -P)
export OHOS_NATIVE
llvm="$OHOS_NATIVE/llvm/bin"
toolchain="$OHOS_NATIVE/build/cmake/ohos.toolchain.cmake"
[ -r "$OHOS_NATIVE/oh-uni-package.json" ] && [ -r "$toolchain" ] &&
    [ -d "$OHOS_NATIVE/sysroot" ] || fail 'OHOS_NATIVE does not contain the native SDK.'
for compiler in clang clang++ llvm-ar llvm-ranlib llvm-readelf; do
    [ -x "$llvm/$compiler" ] || fail "Missing OpenHarmony tool: $llvm/$compiler"
done
for tool in cargo rustup cmake ninja python3; do
    command -v "$tool" >/dev/null || fail "Missing build tool: $tool"
done

rust_target() {
    awk -F '\t' -v abi="$1" '$1 == abi { print $2; found = 1 } END { exit !found }' "$profiles" ||
        fail "Unsupported OpenHarmony ABI: $1"
}

installed=$(rustup target list --installed)
seen=' '
for abi in "$@"; do
    target=$(rust_target "$abi")
    case "$seen" in
        *" $abi "*) fail "Duplicate OpenHarmony ABI: $abi" ;;
    esac
    seen="$seen$abi "
    if ! printf '%s\n' "$installed" | grep -Fxq "$target"; then
        fail "Install the missing Rust target with: rustup target add $target"
    fi
done

# Keep incremental Cargo state tied to the SDK used to build native dependencies.
sdk_key=$({ printf '%s\n' "$OHOS_NATIVE"; cat "$OHOS_NATIVE/oh-uni-package.json"; } | cksum | awk '{print $1}')
cache="$output/build/$sdk_key"
mkdir -p "$cache"
work=$(mktemp -d "$output/stage.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 1' HUP INT TERM
package="$work/package"
cp -R "$platform/har" "$package"
version=$(sh "$repo/platform/sdk/package-assets.sh" version)
for manifest in oh-package.json5 src/main/cpp/types/libgnunet_node/oh-package.json5; do
    sed "s/@GNUNET_SDK_VERSION@/$version/" "$package/$manifest.in" >"$package/$manifest"
    rm "$package/$manifest.in"
done
if [ -n "${GNUNET_BOOTSTRAP_HELLO_DIR:-}" ]; then
    mkdir -p "$package/src/main/resources/rawfile"
    bash "$repo/tools/ci/stage-bootstrap-hellos.sh" "$GNUNET_BOOTSTRAP_HELLO_DIR" \
        "$package/src/main/resources/rawfile/gnunet" >&2
fi
if [ -f "$OHOS_NATIVE/NOTICE.txt" ]; then
    cp "$OHOS_NATIVE/NOTICE.txt" "$package/OPENHARMONY-NOTICE.txt"
fi

compiler_wrapper() {
    cat >"$work/compiler-wrapper" <<'WRAPPER'
#!/bin/sh
set -eu
directory=${0%/*}
case "${directory##*/}" in
    arm64-v8a) machine=aarch64-linux-ohos ;;
    armeabi-v7a)
        machine=arm-linux-ohos
        set -- -march=armv7-a -mfloat-abi=softfp -mtune=generic-armv7-a -mthumb "$@" ;;
    x86_64) machine=x86_64-linux-ohos ;;
    *) exit 2 ;;
esac
exec "$OHOS_NATIVE/llvm/bin/${0##*/}" --target="$machine" \
    --sysroot="$OHOS_NATIVE/sysroot" -D__MUSL__ "$@"
WRAPPER
    chmod +x "$work/compiler-wrapper"
    mv "$work/compiler-wrapper" "$1"
}

notice_targets=
for abi in "$@"; do
    target=$(rust_target "$abi")
    notice_targets="${notice_targets:+$notice_targets }$target"
    key=$(printf '%s' "$target" | tr '-' '_')
    cargo_key=$(printf '%s' "$key" | tr '[:lower:]' '[:upper:]')
    tools="$cache/tools/$abi"
    mkdir -p "$tools"
    compiler_wrapper "$tools/clang"
    compiler_wrapper "$tools/clang++"
    log="$work/$abi.rust.log"
    if ! env "CARGO_TARGET_${cargo_key}_LINKER=$tools/clang" \
        "CC_${key}=$tools/clang" "CXX_${key}=$tools/clang++" \
        "AR_${key}=$llvm/llvm-ar" "RANLIB_${key}=$llvm/llvm-ranlib" \
        cargo rustc --locked --release --lib --jobs "$jobs" --color never \
        --target-dir "$cache/rust" --target "$target" -p gnunet-node-sdk \
        -- --print native-static-libs >"$log" 2>&1; then
        cat "$log" >&2
        fail "Could not build the Rust SDK archive for $abi."
    fi
    native_libs=$(sed -n 's/^note: native-static-libs: //p' "$log")
    [ -n "$native_libs" ] || fail "Rust did not report native link libraries for $abi."
    library_list=''
    for library in $native_libs; do
        case "${library#-l}" in
            ''|*[!a-zA-Z0-9_.+-]*) fail "Unexpected Rust native link library: $library" ;;
        esac
        case "$library" in
            -l*) library_list="${library_list:+$library_list;}$library" ;;
            *) fail "Unexpected Rust native link option: $library" ;;
        esac
    done

    cmake -S "$platform" -B "$work/cmake/$abi" -G Ninja \
        -DCMAKE_TOOLCHAIN_FILE="$toolchain" -DCMAKE_BUILD_TYPE=Release \
        -DOHOS_ARCH="$abi" -DOHOS_PLATFORM=OHOS -DOHOS_STL=c++_static \
        -DGNUNET_RUST_ARCHIVE="$cache/rust/$target/release/libgnunet_node_sdk.a" \
        -DGNUNET_RUST_NATIVE_LIBRARIES="$library_list" >&2
    cmake --build "$work/cmake/$abi" --parallel "$jobs" >&2
    cmake --install "$work/cmake/$abi" --prefix "$package" >&2

    library="$package/libs/$abi/libgnunet_node.so"
    case "$abi" in
        arm64-v8a) machine='AArch64' ;;
        armeabi-v7a) machine='ARM' ;;
        x86_64) machine='Advanced Micro Devices X86-64' ;;
    esac
    elf_header=$(LC_ALL=C "$llvm/llvm-readelf" -h "$library")
    elf_dependencies=$(LC_ALL=C "$llvm/llvm-readelf" -d "$library")
    printf '%s\n' "$elf_header" | grep -Eq "Machine:[[:space:]]+$machine[[:space:]]*$" ||
        fail "Unexpected ELF architecture in $library."
    printf '%s\n' "$elf_header" | grep -Eq 'Type:[[:space:]]+DYN([[:space:]]|$)' ||
        fail "The OpenHarmony module is not a shared library: $library"
    printf '%s\n' "$elf_dependencies" | grep -Fq 'Shared library: [libace_napi.z.so]' ||
        fail "OpenHarmony Node-API dependency is missing: $library"
    if printf '%s\n' "$elf_dependencies" | grep -Eq '\[(libc\+\+(_shared)?\.so|libc\.so\.6)\]'; then
        fail "Unexpected shared C++ runtime or GNU libc dependency in $library."
    fi
done

sh "$repo/platform/sdk/package-assets.sh" notices "$package" $notice_targets >&2
destination="$output/sdk.${work##*.}"
mv "$package" "$destination"
printf '%s\n' "$destination"
