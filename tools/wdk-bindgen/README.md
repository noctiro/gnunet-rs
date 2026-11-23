# Windows kernel binding generation

Generate private `no_std` WFP/WDM/NDIS bindings, compile the SDK's required
macro and inline adapters, and build an unsigned x64 or ARM64 WDM driver. The host tool
uses local SDK packages and writes its outputs under `target/`.

## Inputs and profile

Pass `--target` and supply the corresponding extracted packages at version
**10.0.28000.2526**. Both targets also require `Microsoft.Windows.SDK.CPP` at
that version. Use lowercase package directories under one root and keep each
nuspec and the WDK's `LICENSE.txt`. Verify official archive hashes during SDK
acquisition.

| Target | WDK package | Architecture-specific SDK package |
| --- | --- | --- |
| `x86_64-pc-windows-msvc` | `Microsoft.Windows.WDK.x64` | `Microsoft.Windows.SDK.CPP.x64` |
| `aarch64-pc-windows-msvc` | `Microsoft.Windows.WDK.ARM64` | `Microsoft.Windows.SDK.CPP.ARM64` |

This package's WDK license uses **pre-release terms**. The accepted private
development inputs do not establish permission for live deployment or SDK
redistribution. Review the supplied license; the tool's MPL license does not
grant rights to distribute Microsoft's files. Generated SDK files stay under
`target/` and must not be vendored into the repository.

The checked input profile is fixed:

| Input | Value |
| --- | --- |
| Clang and libclang | Major version 21 |
| MSVC compatibility | 19.44 |
| Kernel/architecture macros | `_KERNEL_MODE=1` and the target's `_AMD64_=1` or `_ARM64_=1` |
| OS declarations | `NTDDI_VERSION=0x0A000012` (`NTDDI_WIN11_BR`), `_WIN32_WINNT=WINVER=0x0A00` |
| NDIS declarations | `NDIS630=1` |

These select header declarations; they do not establish a driver's minimum OS
or runtime support. Supporting a different SDK profile requires a separate
C/Rust ABI comparison. A NuGet version without a prerelease suffix does not
establish a release license.

## Generate and compile

Use existing Clang 21, libclang 21 and locally cached Rust dependencies. From
the repository root:

```sh
LIBCLANG_PATH=/path/to/clang21/lib \
cargo run --offline --locked --jobs 1 --manifest-path tools/wdk-bindgen/Cargo.toml \
  --target-dir target/wdk-bindgen-tool -- \
  --target x86_64-pc-windows-msvc \
  --sdk-root /path/to/extracted-packages \
  --clang /path/to/clang21/bin/clang \
  --out-dir target/wdk-dns-bindings
```

The output directory must be new and its parent must already exist beneath
this repository's `target/`. A Clang filesystem overlay exposes the original
SDK headers with Windows case-insensitive lookup on case-sensitive hosts.
Both libclang and the wrapper compiler use that overlay and the same include
order. The extracted SDK files keep their original names and contents.
Clang's resource directory is explicit. The tool refuses ambient `SDKROOT`,
include-search overrides and `BINDGEN_EXTRA_CLANG_ARGS`. Set `LIBCLANG_PATH`
to select libclang.

## Build the driver

Use the same SDK and Clang inputs and pass `build-driver` with the path to
Rust's `rust-lld` (`rust-lld.exe` on Windows). The selected Rust toolchain must
have `core` and `compiler_builtins` for the specified target. Set
`--rust-sysroot` for an explicit cross sysroot or `--rustc` to select a compiler.

```sh
LIBCLANG_PATH=/path/to/clang21/lib \
cargo run --offline --locked --jobs 1 --manifest-path tools/wdk-bindgen/Cargo.toml \
  --target-dir target/wdk-bindgen-tool -- build-driver \
  --target aarch64-pc-windows-msvc \
  --sdk-root /path/to/extracted-packages \
  --clang /path/to/clang21/bin/clang \
  --lld /path/to/rust-lld \
  --out-dir target/wfp-driver-build
```

The tool stages `package/gnunet-wfp-driver.inf` and
`package/gnunet-wfp-driver.sys` for the same target. `driver-receipt.json` records
both artifacts and the source INF template. Rust checks the generated ABI's
machine identifier at compile time. The tool verifies the PE machine, native entry,
WDK load configuration, unwind data, relocations, ASLR and NX flags, and
kernel/WFP/NDIS imports. Catalog generation and signing use the
[primitive driver package](../../platform/windows/wfp-driver/README.md#package-preparation).

## Generated interface

`bindings.rs` contains `core`-based SDK types, constants and the selected native
exports, including datagram IPv4/IPv6 field identifiers, incoming flow metadata,
WFP policy management, `NdisGetDataBuffer` and the actual
`WdmlibIoCreateDeviceSecure` declaration. Status values derived from SDK macros
use the `GNUNET_WFP_STATUS_*` names.

`wrapper.h`, `wrappers.c` and `wrappers.obj` adapt actual SDK macros/inlines:
IRP completion, pending state and current stack; spin-lock operations and IRQL;
original user event references; and read-only NBL/NB traversal, status, data extent and current-MDL access. They contain
no DNS, routing, driver registration or protocol logic. The Rust caller must
supply live native objects and satisfy the SDK's IRQL/locking contracts.

Compile-only wrapper diagnostics and exact arguments are retained as JSON.
`receipt.json` records the fixed profile, tool source hashes, included SDK/header
hashes, compiler versions and generated artifact hashes, including the include
overlay. The receipt covers generation and wrapper compilation.
