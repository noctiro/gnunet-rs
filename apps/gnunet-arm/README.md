# GNUnet ARM CLI

`gnunet-arm` controls service startup, shutdown, listing and monitoring through the
Rust [ARM client host](../../adapters/arm-std/README.md). Protocol state and command
phases are shared on Linux, macOS, Windows and FreeBSD.

## Build and use

```sh
cargo build --locked -p gnunet-arm-cli -p gnunet-arm-host --bins
target/debug/gnunet-arm --help
target/debug/gnunet-arm -c /path/to/owned.conf -I
```

Use `gnunet-arm.exe` on Windows. Local ARM launch uses the native Windows process
and bootstrap layers; it requires no Unix spawn helper. Unix installations supply
`gnunet-arm-spawn-helper`, discovered alongside the CLI or through ProjectData's
libexec layout.

## Configuration and output

The CLI loads normal GNUnet configuration and preserves the `arm.CONFIG` fallback.
`--help` lists ARM and PROGRAM options. PREFIX/OPTIONS are GNUnet command fragments;
Windows executable and configuration filenames retain their native argument
boundaries. No shell expansion is performed.

PROGRAM logging selects `-L/-l` and the existing forced/default log environment
values. Control, monitor, Resolver and logging share the selected clock. Business
stdout/stderr remain separate from Logger output. Immediate option results
precede logger/file/runtime setup.

The standalone entry applies the configured testing skew, then owns the shared
scoped `SPEEDUP_INTERVAL`/`SPEEDUP_DELTA` task on that same clock. `--timeout`
retains a logical deadline and rearms on clock changes. Returning or canceling
the run retires only its original speedup ticket. Resolver ownership remains
outside the scheduled command task, preserving disconnect and its independent
error even when the scheduler fails. Embedding `runtime::run` leaves speedup
scheduling with its caller.

`--delete` applies only when the command reducer selects deletion. It removes
configured files/directories without following link or reparse-point targets.
Use it only for directories whose namespace you control; concurrent replacement
of entries must be excluded.

## Locale and catalogs

The packaged binary selects the explicit disabled-NLS profile.
`runtime::main_with_locale` accepts a caller-selected PROGRAM `LocaleSetup`,
including the shared native `ProcessLocale`. Setup precedes parsing and native
owners. The retained backend supplies help, option diagnostics, status templates
and Logger messages; its case context also reaches configuration and log policy.
Enabled failures stop the command without selecting English output as fallback.
Native service names and filenames remain arguments to typed formatting, including
when a catalog reorders arguments.

`options::parse_localized`, `runtime::configuration_with_locale`,
`diagnostics::Selection::with_locale` and `state::State::with_locale` expose the same composition to embedding callers. A
state output failure stays latched after `take_output_error`; later callbacks
cannot resume output or authorize deletion. Locale-bearing CLI owners stay on
the caller's thread; protocol state and native process ownership remain separate.

## Embedding and ownership

`runtime::run` consumes an `Invocation` containing configuration, options, native
ports and diagnostics, and borrows a caller-owned `ChildRegistry`. `Ports` carries
the C ABI profile and, on Unix, the helper deployment. Cancellation and disconnect
retire callback authority without implicitly terminating locally launched ARM.
See the [design](DESIGN.md) and [host ownership contract](../../adapters/arm-std/API.md)
for bootstrap and completion-resource lifetimes.

## Verification

Portable parser/reducer tests cover literal output and phase behavior. Native
Windows cases preserve UTF-16 path/argument units and exercise readonly deletion.
The host's Windows process fixture covers real launch, readiness and cancellation.
Those native cases must execute on Windows; a cross-compiled target is a build
check. Global interoperability and platform qualification are tracked in
[implementation status](../../IMPLEMENTATION_STATUS.md).
