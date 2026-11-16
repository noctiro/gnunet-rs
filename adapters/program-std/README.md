# PROGRAM host

Shared command preparation, GETOPT, logging, locale, clock and daemon lifecycle
for normal applications. Local argument processing preserves Unix bytes and
Windows UTF-16 code units through the [native string adapter](../native-std/API.md#local-command-and-path-bytes).
Configuration filename support follows the [CONFIG constraints](../config-std/README.md).

## Public interfaces

`program::native_path` decodes local PROGRAM/getopt argument bytes without loss,
filesystem I/O or expansion. Applications use this interface for native paths;
protocol text encoding remains separate.

- [Public API](API.md): preparation, scoped execution, logging and daemon ownership.
- [Design](DESIGN.md): module boundaries and scheduling policy.
- [Native contracts](NATIVE-CONTRACT.md): process, stream and locale capabilities.
- `foreground::Stop`: original native/parent subscriptions, scheduler cancellation latch and selected diagnostic failure.
- [Binary I/O](BINARY_IO.md): bounded file/stdio requests and original-work retirement.

A prepared main capability is distinct from option-processing output. Scoped
execution owns bounded tasks; stopping or dropping it retires its work. Process
locale/stderr and daemonization require their documented native capabilities.

## Service startup

`service::native::Application` supplies a service's configuration section,
validated settings, local credential policy and caller-driven business loop.
The native driver owns once-only inheritance capture, SERVICE option selection,
configuration loading, process identity, listener completion and one current-thread
runtime. Applications retain their protocol, Resolver and independent cleanup
owners. SET, SETI, SETU, CONSENSUS, CADET, Conversation, Messenger, SECRETSHARING,
ABD, REGEX, RPS and RECLAIM use this driver.

Call `service::native::main::<Application>()` once as the fresh executable's first
initialization, under its explicit unsafe inheritance contract. The application
can instead use `service::native::run` to retain pre-diagnostic failures as typed
errors. Both entries preserve help, parser and application exit status; failures
already sent through the selected Reporter are not emitted again on stderr.
The application receives borrowed configuration/listeners, owned validated settings, its shared clock and Reporter,
original stop subscriptions and a consuming `Readiness` capability. Signal that
capability only after the application's actual readiness predicate. Its finite
wait observes logging and native/parent stop; cancellation retains any admitted
original status. Windows startup failure cannot replace an admitted READY, and
independent failure-notification errors remain attached to the original cause.
Owned settings allow unique layout, storage or provider policies to move into
their business owners without cloning them or hiding ownership in shared cells.

Unix prepares inherited/TCP listeners before applying the configured identity,
then completes local endpoints under that identity. Windows verifies the configured
process token, adopts native activation, and selects managed console detachment
or qualified standalone re-exec. Selected diagnostics and physical application
cleanup remain independent of parent readiness submission.

`service-runtime` includes the Tokio-backed `runtime` feature. On Windows,
`service::detach` composes the shared native
startup and original-child retirement APIs for normal service executables.
Call it outside an asynchronous context with the selected runtime and owned
activation. Readiness or launch failure stays primary; independent retirement
failure retains the original registry, bootstrap and listener owners in
`DetachFailure` for explicit `retry_retirement`. Drop never kills or waits for a
child. Protocol hosts and storage do not depend on this CLI composition.

`service::acknowledge_ready` drives one original startup notification under a
fixed native deadline while observing the selected Reporter and native/parent
stop. Keep its readiness writer outside the wait future to retain an admitted
intent through cancellation. NAMECACHE and GNS use the same helper.
`StopSubscription` also lets an application retain its cancellation state while
delegating the same original native stop source. Readiness waits poll that wrapper
rather than bypassing it or inferring a stop from an error number.
