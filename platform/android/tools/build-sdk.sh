#!/usr/bin/env bash
# Build and package the Android library from current Rust, JNI and Kotlin sources.
# NDK target/API mapping: https://developer.android.com/ndk/guides/other_build_systems
# Gradle/JDK compatibility: https://developer.android.com/build/releases/agp-8-13-0-release-notes
# Gradle distribution hash: https://gradle.org/release-checksums/#v8.13
set -euo pipefail

tools_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
profile="$tools_dir/sdk_profile.py"
case "${1:-}" in
    --sdk-packages)
        exec python3 -B "$profile" sdk-packages ;;
    --rust-targets)
        exec python3 -B "$profile" rust-targets ;;
    --help|-h)
        printf '%s\n' 'Usage: bash platform/android/tools/build-sdk.sh' \
            'Requires Linux x86_64 or macOS, Python3.11+, JDK17, ANDROID_HOME and packages from --sdk-packages.' \
            'Install the targets from --rust-targets first. Downloads a verified Gradle distribution.' \
            'Publishes a flat AAR and a ZIP with its Maven dependency metadata.' \
            'GNUNET_ANDROID_OUTPUT selects output (default target/android-sdk).' \
            'GNUNET_BOOTSTRAP_HELLO_DIR optionally supplies local bootstrap HELLO files.' \
            'GNUNET_ANDROID_BUILD_JOBS selects positive Cargo/Gradle concurrency (default1).'
        exit 0 ;;
esac
if [[ $# != 0 ]]; then printf 'Unexpected build-sdk argument\n' >&2; exit 2; fi

repo=$(CDPATH='' cd -- "$tools_dir/../../.." && pwd)
cd "$repo"
sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
: "${sdk:?Set ANDROID_HOME to the Android SDK directory}"
: "${JAVA_HOME:?Set JAVA_HOME to a JDK17 installation}"
sdk=$(CDPATH='' cd -- "$sdk" && pwd)
for tool in cargo rustup python3 curl unzip; do command -v "$tool" >/dev/null; done
python3 -B -c 'import sys; assert sys.version_info >= (3, 11), "Python3.11 or later is required"'
plan=$(python3 -B "$profile" build-plan)
read -r min_sdk compile_sdk build_tools ndk_version cmake_version gradle_version gradle_sha <<< "$plan"
targets=${plan#*$'\n'}
version=$(sh "$repo/platform/sdk/package-assets.sh" version)
jobs=${GNUNET_ANDROID_BUILD_JOBS:-1}
if [[ ! $jobs =~ ^[1-9][0-9]*$ ]]; then printf 'Build jobs must be positive\n' >&2; exit 2; fi
case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) host=linux-x86_64 ;;
    Darwin/arm64|Darwin/x86_64) host=darwin-x86_64 ;;
    *) printf 'Unsupported Android NDK build host\n' >&2; exit 2 ;;
esac
ndk="$sdk/ndk/$ndk_version"
bin="$ndk/toolchains/llvm/prebuilt/$host/bin"
test -x "$bin/llvm-ar"
test -x "$sdk/cmake/$cmake_version/bin/cmake"
test -f "$sdk/platforms/android-$compile_sdk/android.jar"
test -x "$sdk/build-tools/$build_tools/aapt2"
if [[ $(awk '$1 == "Pkg.Revision" { print $3 }' "$ndk/source.properties") != "$ndk_version" ]]; then
    printf 'Unexpected Android NDK revision\n' >&2; exit 1
fi
java_version=$("$JAVA_HOME/bin/java" -version 2>&1)
if ! grep -Eq 'version "17[.]' <<< "$java_version"; then
    printf 'This SDK build requires JDK17\n' >&2; exit 1
fi

installed=$(rustup target list --installed)
while read -r abi target compiler; do
    if ! grep -Fxq "$target" <<< "$installed"; then
        printf 'Missing Rust target: %s\n' "$target" >&2; exit 1
    fi
    driver="$bin/${compiler}${min_sdk}-clang"
    if [[ ! -x "$driver" ]]; then
        printf 'Missing Android compiler for %s: %s\n' "$abi" "$driver" >&2; exit 1
    fi
done <<< "$targets"

output=${GNUNET_ANDROID_OUTPUT:-"$repo/target/android-sdk"}
mkdir -p "$output"
output=$(CDPATH='' cd -- "$output" && pwd)
work=$(mktemp -d "$output/build.XXXXXXXX")
logs="$work/logs"
project="$work/platform/android"
archives="$work/archives"
mkdir -p "$logs" "$project" "$work/platform/sdk/include" "$archives"
cp platform/android/{build.gradle.kts,settings.gradle.kts,consumer-rules.pro,sdk-profile.properties} "$project/"
cp -R platform/android/src "$project/"
cp platform/sdk/include/gnunet_node.h "$work/platform/sdk/include/"
if [[ -n ${GNUNET_BOOTSTRAP_HELLO_DIR:-} ]]; then
    mkdir -p "$project/src/main/assets"
    bash tools/ci/stage-bootstrap-hellos.sh "$GNUNET_BOOTSTRAP_HELLO_DIR" "$project/src/main/assets/gnunet"
fi
python3 -B - "$project/local.properties" "$sdk" "$sdk/cmake/$cmake_version" <<'PY'
import sys
from pathlib import Path
def property_value(value):
    data = value.encode('utf-16-be')
    return ''.join(f'\\u{int.from_bytes(data[i:i+2], "big"):04x}' for i in range(0, len(data), 2))
Path(sys.argv[1]).write_text('sdk.dir=' + property_value(sys.argv[2]) + '\ncmake.dir=' +
                            property_value(sys.argv[3]) + '\n', encoding='ascii')
PY
export PATH="$JAVA_HOME/bin:$sdk/cmake/$cmake_version/bin:$PATH"

run_log() {
    local name=$1
    shift
    printf 'Android SDK: %s\n' "$name"
    if ! "$@" >"$logs/$name.log" 2>&1; then
        tail -n 160 "$logs/$name.log" >&2
        return 1
    fi
}

zip="$work/gradle-$gradle_version-bin.zip"
run_log gradle-download curl --fail --silent --show-error --location --retry 3 \
    "https://services.gradle.org/distributions/gradle-$gradle_version-bin.zip" -o "$zip"
run_log gradle-check python3 -B - "$zip" "$gradle_sha" <<'PY'
import hashlib, sys
from pathlib import Path
with Path(sys.argv[1]).open('rb') as distribution:
    if hashlib.file_digest(distribution, 'sha256').hexdigest() != sys.argv[2]:
        raise SystemExit('Gradle distribution checksum mismatch')
PY
run_log gradle-unpack unzip -q "$zip" -d "$work"
gradle="$work/gradle-$gradle_version/bin/gradle"

while read -r abi target compiler; do
    driver="$bin/${compiler}${min_sdk}-clang"
    variable=$(printf '%s' "$target" | tr '[:lower:]-' '[:upper:]_')
    run_log "rust-$abi" env "CARGO_TARGET_${variable}_LINKER=$driver" \
        "CC_${target//-/_}=$driver" "AR_${target//-/_}=$bin/llvm-ar" \
        cargo rustc --locked --release --lib --jobs "$jobs" \
        --target-dir "$output/rust" --target "$target" --color never -p gnunet-node-sdk \
        -- --print native-static-libs </dev/null
    if ! awk 'sub(/^note: native-static-libs: /, "") { print; found = 1; exit }
              END { if (!found) exit 1 }' "$logs/rust-$abi.log" >"$logs/$abi.libs"; then
        printf 'Missing native static link dependencies for %s\n' "$target" >&2; exit 1
    fi
    # The existing CMake target supplies these libraries; libc is implicit in
    # the NDK compiler driver. Refuse an unhandled new native dependency.
    read -r -a libraries < "$logs/$abi.libs"
    for library in "${libraries[@]}"; do
        case "$library" in
            -lc|-ldl|-llog|-lm|-lunwind) ;;
            *) printf 'Update Android CMake linkage for %s: %s\n' "$target" "$library" >&2; exit 1 ;;
        esac
    done
    mkdir "$archives/$abi"
    cp "$output/rust/$target/release/libgnunet_node_sdk.a" "$archives/$abi/"
done <<< "$targets"

sdk_notice_targets=()
while read -r _ target _; do
    sdk_notice_targets+=("$target")
done <<< "$targets"
run_log licenses sh "$repo/platform/sdk/package-assets.sh" notices \
    "$project/src/main/assets/gnunet-notices" "${sdk_notice_targets[@]}"

run_log aar "$gradle" --no-daemon --console plain --max-workers "$jobs" -p "$project" \
    publishReleasePublicationToSdkRepository \
    "-PgnunetNodeArchives=$archives" \
    "-PgnunetNodeVersion=$version"

python3 -B "$tools_dir/verify_aar.py" "$project" "$bin/llvm-readelf" "$logs" "$output" "$version"
printf 'Android SDK build logs: %s\n' "$logs"
