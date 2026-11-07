# Official Resolver Unix host

This workspace adapter executes the GNUnet request4/response5
service over Unix/TCP streams and the existing UDP DNSSTUB host. It uses the
frozen borrowed Resolver core, complete DNS parser and explicit native IDNA
backend. Production library code forbids unsafe Rust and C FFI. The foreground
binary has explicit narrowly scoped activation capture and fresh-process daemon
separation; neither operation is hidden in the generic async host. The package introduces no protocol fields or official configuration keys.

`src/lib.rs`, `io.rs`, `storage.rs` and `startup.rs` form the host adapter. `../../apps/gnunet-service-resolver` contains the foreground application. `examples/fixture.rs` is a separate test executable with caller-supplied fixture
files and an owned loopback endpoint. Its arguments are not production options
or GNUnet configuration extensions. The fixture is separate from the production app and its arguments. Both packages
are integrated with workspace dependency policy and the optional SDK feature.

## Ownership and cancellation

The caller owns two fallibly allocated, initialized `Store` values and an IDNA
Workspace. `Host` takes a `Resolver` plus its equal-geometry transaction Scratch,
borrows the backend, and owns streams, a DNSSTUB host and bounded queues. No object stores a reference into its own backing allocation. A core output view
is encoded and copied into persistent TX ownership before its EffectTicket is
released. A full TX queue retains `current_effect`; subsequent drives continue
stream writes and bounded RX dispatch. Other clients can reach EOF even
while an unrelated output is blocked. Core admission capacity closes only the
responsible physical client, never fabricates a successful result.

`Host::admit` consumes a shared runtime `AcceptedConnection` for embedding with
caller-owned acceptance. It uses the same ACL, Unix credential, capacity and
native diagnostic path as `drive`; rejected connections close at that boundary.

StartQuery calls stub admission and explicitly detaches Admission.evicted
from the old lookup. If adoption fails, the newly admitted token is
canceled before reporting unavailability/releasing the lease. Normal send errors
leave the stub's original retry active. StartQuery compares its original deadline
before minting a token: a start delayed past 30 seconds is retired by the core
without sending an expired query. Existing due timers also run before a held
DNS datagram is processed.

A DNS callback copies its bytes, original token and callback UTC into one
persistent bounded receive slot. Resource refusal retains that exact datagram
and returns an observable error with the original core state intact. Another
receive cannot overwrite it. Transient TX/effect pressure is drained before
processing it; a permanent pool/metadata limit remains an explicit repeatable
error. Its TTL UTC is fixed across capacity retry; current cache evaluation uses current
UTC. A callback with unavailable UTC is explicitly rejected and discarded without
changing the original lookup deadline; a later fresh response can recover. Cleanup that exceeds one work budget yields and continues before another UDP poll. The packet is parsed with the parser and every name is projected
through the native backend. URI is bytes, not an IDNA name. No additional QR,
rcode, question, traffic-class or fixed A/AAAA-width filter is added.

RX/TX offsets, queued frames, associations, the pending datagram and original
monotonic deadlines are Host fields. Canceling a drive future drops only wait
futures, without replaying submitted frames or resetting timers. DropClient first
drops its stream and TX queue, then releases the close lease. Stop closes
all client streams and stub sockets before releasing Stop. The caller owns
listeners; the foreground assembly drops BoundListeners and its created path
guards after stopping the host. Inherited Unix paths keep parent ownership.

## Native startup and explicit resource scope

The production binary reads only literal `/etc/hosts` and `/etc/resolv.conf` once. Each file has a caller-selected 16 MiB byte ceiling in the foreground profile;
file or resource failures produce path-qualified diagnostics and an empty
failed-file input, preserving upstream startup continuation. It never writes
these files or calls system NSS/DNS for resolver requests. Parsed literal
nameserver addresses are added in file order at port53. Invalid IP syntax is
counted; server-array exhaustion is an explicit error. Missing upstreams keep the
original 30-second service timer, without early END.

Configuration, ACLs, listener binding and activation use the shared native
service runtime with section `resolver`. Default shutdown is Immediate, matching
GNUNET_SERVICE_OPTION_NONE. Soft exists only as an explicitly selected library
operation and waits for connected clients rather than lookup count. The binary
uses the shared standard SERVICE options/logger and explicit daemon ready pipe. Its standard main retains activation and prebound TCP before configured USERNAME,
then finishes new Unix listeners and reads literal machine files as that account. Actual Unix admission uses shared kernel UID-first/GID-or-group checks; absent
flags are false. Generic async embedding never changes process identity and
verifies a configured account against real/effective IDs.

`Host::set_runtime_clock` installs one RuntimeClock Arc and exclusive
subscription immediately after Host::new, before machine data/endpoints/admission/drive. All UTC cache/receive evaluation uses this original source; native epoch,
entropy functions and original scheduling deadlines are unchanged. Once data or
lookup work starts the source cannot be replaced. Logical changes are polled in
the drive waiter, alongside native I/O/timers. Clock errors and all other
post-construction failures still take the same Immediate physical shutdown;
subscription retirement and client/UDP closes require no new clock sample. `startup::foreground_listening_with_clock` consumes the finished listeners;
Ready follows Host construction/loading. Original drive/Ready error and
independent cleanup failure are retained together with the physical report. The existing foreground embedding delegates to that same implementation with
native UTC and requires an already prepared identity. Linux, Darwin and FreeBSD family selection is explicit; other native
family ABIs return Unsupported.

Default logical geometry is clients64/lookups128/hosts1024/buckets1025/records4096/
effects512, with two independent 8 MiB aggregate byte pools. Legal record width
is65535, independently of aggregate capacity. Host TX is256 KiB per connection,
DNS receive65535, expanded parse arena4 MiB, query slots13104 and record slots5956. All allocations are bounded/fallible; allocation metadata overhead and kernel
buffers are outside these explicit byte counts. Diagnostic counters saturate at
u64::MAX as lower bounds and cannot abort or replay a business commit.

## Checks

`tests/loopback.rs` contains thirteen named tests, including true partial stream
I/O, Unix/TCP clients, IPv6 UDP PTR, Unicode IDNA, Any sequencing, malformed and
wrong-ID isolation, eviction ownership, EOF cleanup, canceled-drive resume,
kernel TX backpressure, retained resource-error datagrams and recovery,
queued-start expiry, and both paused-clock boundary and wall-clock
30-second timer wakeups. The wall-clock test actually waits30 seconds.

`tools/public_client.c` calls the unchanged normal C public API. Its process
oracle drives the Rust foreground fixture over Unix and TCP and the script's own
UDP server, including A/AAAA/Any/PTR4/PTR6, cancellation, Unicode, negative/malformed
cases, concurrent C clients and physical cleanup. It never substitutes a C-only
or mock socket result for a Rust operation. `build_probe.py` reuses an existing
normal Meson compiler profile and immutable libgnunetutil; it rebuilds only the
small caller. `verify.py` records fresh commands, exact nonzero test names,
input and artifact hashes and before/after dependency bindings.

These are component implementation receipts; owner verification remains pending.

Workspace entry: `cargo run -p gnunet-service-resolver -- -c official.conf`. The optional SDK feature `official-resolver` exports `gnunet::resolver_host`;
default/no-allocation builds retain only the pure `resolver_service` core. The maintained verifier builds the separate app and adapter, uses a new
output-local target and pinned toolchain, and runs all13 socket witnesses
plus three recovery regressions,15 normal-C process checks and15 production
process checks before binding inputs.

The new standard-entry/selected-clock/credential source passes central macOS
and Linux target compilation.
