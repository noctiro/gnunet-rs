#!/bin/sh
set -efu

usage() {
    printf 'Usage: %s [--intel-simulator] [--rust-targets | --link-profiles]\n' "$0"
}

intel=false
if [ "${1:-}" = --intel-simulator ]; then
    intel=true
    shift
fi

profiles() {
    printf '%s\n' 'aarch64-apple-ios iphoneos arm64' 'aarch64-apple-ios-sim iphonesimulator arm64'
    if "$intel"; then
        printf '%s\n' 'x86_64-apple-ios iphonesimulator x86_64'
    fi
}

if [ "$#" -eq 1 ]; then
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --rust-targets) profiles | cut -d ' ' -f 1; exit ;;
        --link-profiles) profiles | cut -d ' ' -f 2-; exit ;;
    esac
fi
if [ "$#" -ne 0 ]; then
    usage >&2
    exit 2
fi

repo=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo"
ios="$repo/platform/ios"
output="$repo/target/ios"
archive=libgnunet_node_sdk.a
configurations=$(profiles)

installed=$(rustup target list --installed)
while read -r target _; do
    if ! printf '%s\n' "$installed" | grep -Fxq "$target"; then
        printf 'Install the missing Rust target with: rustup target add %s\n' "$target" >&2
        exit 1
    fi
done <<EOF
$configurations
EOF

mkdir -p "$output"
work=$(mktemp -d "$output/stage.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 1' HUP INT TERM

build_archive() {
    sdkroot=$(xcrun --sdk "$2" --show-sdk-path)
    log="$work/$1.log"
    if ! SDKROOT="$sdkroot" IPHONEOS_DEPLOYMENT_TARGET=15.0 \
        cargo rustc --locked --release --lib --jobs "${GNUNET_IOS_BUILD_JOBS:-1}" \
        --target-dir "$output/rust" --target "$1" --color never -p gnunet-node-sdk \
        -- --print native-static-libs </dev/null >"$log" 2>&1; then
        cat "$log" >&2
        exit 1
    fi
    if ! awk 'sub(/^note: native-static-libs: /, "") { print; found = 1; exit }
              END { if (!found) exit 1 }' "$log" >"$work/$1.libs"; then
        cat "$log" >&2
        printf 'The Rust compiler did not report native static link dependencies for %s.\n' "$1" >&2
        exit 1
    fi
}

link_item() {
    case "$2" in
        ''|*[!a-zA-Z0-9_.+-]*)
            printf 'Unexpected Apple native link dependency: %s\n' "$2" >&2
            exit 1 ;;
    esac
    printf '    link %s"%s"\n' "$1" "$2"
}

stage_headers() {
    mkdir -p "$1"
    cp "$repo/platform/sdk/include/gnunet_node.h" "$repo/platform/sdk/include/gnunet_dns_proxy.h" "$1/"
    {
        sed '$d' "$ios/module.modulemap"
        libs=$(cat "$work/$2.libs")
        set -- $libs
        while [ "$#" -gt 0 ]; do
            case "$1" in
                -framework) link_item 'framework ' "${2:-}"; shift ;;
                -l*) link_item '' "${1#-l}" ;;
                *) printf 'Unexpected Apple native link option: %s\n' "$1" >&2; exit 1 ;;
            esac
            shift
        done
        printf '}\n'
    } >"$1/module.modulemap"
}

device=
simulator=
simulator_target=
while read -r target sdk _; do
    build_archive "$target" "$sdk"
    slice="$output/rust/$target/release/$archive"
    case "$sdk" in
        iphoneos)
            stage_headers "$work/device-headers" "$target"
            device="$slice" ;;
        iphonesimulator)
            if [ -z "$simulator" ]; then
                stage_headers "$work/simulator-headers" "$target"
                simulator_target="$target"
                simulator="$slice"
            else
                if ! cmp -s "$work/$simulator_target.libs" "$work/$target.libs"; then
                    printf 'Simulator slices have different native link dependencies.\n' >&2
                    exit 1
                fi
                merged="$work/$target-$archive"
                xcrun lipo -create "$simulator" "$slice" -output "$merged"
                simulator="$merged"
            fi ;;
    esac
done <<EOF
$configurations
EOF

package="$work/package"
mkdir "$package"
cp "$ios/Package.swift" "$package/"
cp -R "$ios/Sources" "$package/"
targets=$(printf '%s\n' "$configurations" | cut -d ' ' -f 1)
sh "$repo/platform/sdk/package-assets.sh" notices "$package" $targets >&2
if [ -e "$package/Sources/GNUnetNode/Resources/gnunet" ]; then
    printf 'Pass optional HELLO resources through GNUNET_BOOTSTRAP_HELLO_DIR instead of source-tree resources.\n' >&2
    exit 1
fi
if [ -n "${GNUNET_BOOTSTRAP_HELLO_DIR:-}" ]; then
    bash "$repo/tools/ci/stage-bootstrap-hellos.sh" "$GNUNET_BOOTSTRAP_HELLO_DIR" \
        "$package/Sources/GNUnetNode/Resources/gnunet"
fi
xcodebuild -create-xcframework \
    -library "$device" -headers "$work/device-headers" \
    -library "$simulator" -headers "$work/simulator-headers" \
    -output "$package/GNUnetNodeNative.xcframework" >&2
destination="$output/sdk.${work##*.}"
mv "$package" "$destination"
printf '%s\n' "$destination"
