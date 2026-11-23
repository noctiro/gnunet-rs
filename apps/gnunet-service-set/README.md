# Normal generic SET service

This standard SERVICE entrypoint composes the independent old generic SET core
with the bounded CADET host. It uses the `set` endpoint and its original
union/intersection formats, including explicit C ABI placement and native IBF
columns. It does not redirect public SET operations to SETI or SETU.

## Startup and configuration

Official options/configuration, inherited listeners, configured process identity,
ACL/kernel-credential admission, one shared clock, explicitly driven Resolver,
finite startup and independent shutdown use the shared process facilities. READY
requires CADET MQ attachment. No fixed main port, RPS sampler or discovery
actor is started. Client Listen opens only its exact requested application port.

The shared [Unix entry](../../adapters/program-std/src/service/native/unix.rs)
handles privilege changes and fork detachment. The shared
[Windows entry](../../adapters/program-std/src/service/native/windows.rs)
handles process-token identity verification,
native socket activation, managed console detachment or standalone re-exec,
and original-parent control/readiness. Both drive the same foreground loop and
physical cleanup. Readiness submission has a finite bound; an admitted status
cannot be replaced after a timeout. Initialization and notification failures
remain separate errors.

`[set]` selects the official listeners and service options. `[set-rust]` selects
resource bounds and the explicit native SET ABI. Missing `UNIX_MATCH_UID` and
`UNIX_MATCH_GID` default to YES on Unix and NO on Windows. On Windows
both options use the
[configured listener's DACL](../../adapters/service-runtime/README.md#configured-local-listeners).

Run `gnunet-service-set -c service.conf`; use `-d` to select native detachment.

## Operation ownership

An accepted incoming operation retains its original physical CADET channel when
ownership transfers to its accepting set; later listener retirement leaves that
accepted operation alive. Original effect and partial/whole-write facts remain
separate from remote completion. There is no invented cancellation ACK.
