# Native NSE subscription and command

This package implements official NSE subscriptions over shared CLIENT, framing
and clock ports. Protocol state lives in `gnunet_client::nse`; NSE algorithms,
PoW, private keys and service ownership are separate.

## Subscription API

`Subscription::new(&mut Instance, EndpointSource, Option<Bounds>, Limits)`
reserves one original source. `poll`/`drive` selects an endpoint, attaches the
native socket, writes the immutable four-byte START321 and receives fixed
32-byte ESTIMATE323 frames. Each observation belongs to its original pure epoch.
A complete START write is a local write fact, not readiness or an estimate.

Well-framed unknown messages are ignored; malformed known frames retire only
that source. Binary64 bits, NaN deviation, signed zero and repeated/older timestamps
are preserved. Estimates are public statistical observations, not authenticated
peer counts.

Partial framing survives canceled waits. `close` physically closes first, then
invalidates the epoch and latest state; there is no wire CANCEL/DONE. Loss reports
retain the exact epoch and START write prefix. Replacement uses a new epoch and
subscription without replaying old callbacks or suffixes. Reconnect backoff
resets only after a matching valid estimate, as in the active official API.
Clock/Resolver refusal requires explicit recovery.

## Resource and time bounds

Optional total `Bounds` use the shared runtime's immutable canonical and native
targets across reconnection. Admission captures the native target before clock
sampling and checks it again afterward. A missing total permits continuous monitoring. Each selected
source still has a default 24-hour lifetime, attachment-to-first-estimate has a
30-second native bound, and partial input has an independent ten-second bound.
`poll_native_guard` checks these before outer output or Resolver work. Logical
clock adjustment cannot extend an original native target or revive an old source.

Retained data is one START frame, one bounded receive frame, one latest public
observation and constant metadata/timers. No hidden Resolver or service is created.

## PROGRAM integration

The `program` feature exposes `cli::scheduled` and its explicit captured parent
control input. It uses one shared PROGRAM, clock, Resolver and native stop owner.
The [installed command](../../apps/gnunet-nse/) prints one estimate by default;
`-m` monitors until stop or an explicit finite monitor target.

`[nse-client-rust]` provides `FIRST_ESTIMATE_TIMEOUT`, `MONITOR_TIMEOUT`,
`SOURCE_LIFETIME`, `INITIAL_TIMEOUT`, `INPUT_TIMEOUT` and `OUTPUT_TIMEOUT`.
These are local client budgets and do not configure PoW or the NSE service.

## Native output and retirement

One fixed 2048-byte line and a capacity-one 2048-byte I/O worker own stdout.
Windows consoles use native text output; redirected bytes remain exact. The
worker never changes shared descriptor flags or blocks the network driver.
Positive native counts advance only the original line; an interrupted/uncertain
write fails without replaying its prefix. Backpressure stops further estimate
reception while that line remains pending.

The output owner outlives the cancellable PROGRAM task. After PROGRAM finishes,
a separate one-second retirement observes the original transfer and actual
flush/close, retaining their independent errors. A blocked syscall can outlive
that wait; no timeout claims force-cancellation, rollback, thread join, directory
durability or downstream consumption.

Success requires a complete real estimate line. Finite monitoring succeeds after
its configured target only if a full line was delivered and none remains pending.
Signals before an estimate yield status 1; completed monitor output may exit 0.
Incomplete output or runtime failure yields 1; preparation errors yield 2.

## SDK

`official-nse-client` exposes `gnunet::clients::nse::native`; pure state is at
`gnunet::clients::nse`. The native library supports Unix and Windows without
requiring its PROGRAM feature. See the central
[compatibility contract](../../spec/gnunet/compatibility.md) for external
interoperability requirements.
