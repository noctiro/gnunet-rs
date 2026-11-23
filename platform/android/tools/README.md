# Android SDK package builder

`build-sdk.sh` builds the current Rust static library, JNI shared libraries and
Kotlin API into one release AAR for `arm64-v8a`, `armeabi-v7a`, `x86_64` and
`x86`. It stages the [Android project](../README.md) and common C header
together under `target/android-sdk/`. The release variant also supplies a
local Maven repository for application builds.

## Requirements and invocation

Use Linux x86_64 or macOS with Bash, Python 3.11 or later, JDK 17, Cargo, rustup,
curl and unzip. Set `JAVA_HOME` and `ANDROID_HOME`. The [SDK profile](../sdk-profile.properties)
defines the minimum and compile APIs, SDK tools, ABIs and Rust targets used by
the builder, Gradle and CI.

```sh
bash platform/android/tools/build-sdk.sh --sdk-packages
bash platform/android/tools/build-sdk.sh --rust-targets
bash platform/android/tools/build-sdk.sh
```

Install the packages and Rust targets printed by the first two commands before
building. The builder verifies the Gradle distribution against the profile's
SHA-256 and runs it with the [staged Gradle project](../build.gradle.kts).
[Gradle checksums](https://gradle.org/release-checksums/) ·
[AGP compatibility](https://developer.android.com/build/releases/agp-8-13-0-release-notes#compatibility)

Set `GNUNET_ANDROID_OUTPUT` to choose another output directory and
`GNUNET_ANDROID_BUILD_JOBS` to choose positive Cargo/Gradle concurrency; its
default is one. Logs and intermediate files remain in the output directory.

Set `GNUNET_BOOTSTRAP_HELLO_DIR` to package explicitly selected local HELLO
files. The [shared asset builder](../../../tools/ci/stage-bootstrap-hellos.sh)
produces the indexed assets consumed by the SDK's opt-in installer.

## Artifact checks

The builder checks all four JNI ELF architectures, Kotlin classes, JNI
exports, static Rust ABI linkage and system-library dependencies. The 64-bit
ELF load segments must support 16 KB pages. Packaged bootstrap assets must
match the staged files byte for byte.

The local Maven repository uses the version of the workspace Rust SDK crate.
Its AAR must be identical to the compiled release AAR. The builder verifies
the publication coordinates and Kotlin standard library dependency in the
POM and Gradle runtime variant before producing these files.

- `gnunet-node-android-maven.zip` contains the Maven repository under `maven/`,
  alongside `LICENSE` and `NOTICE.md`.
- `gnunet-node-android.aar` contains the verified release variant.
- `artifact.json` records the profile, Maven coordinate and SHA-256 of each artifact.

[Application integration](../README.md#add-the-sdk-to-an-app) ·
[Android local Maven publishing](https://developer.android.com/build/publish-library/upload-library#local-repo)
