# Official Resolver native host

This workspace adapter executes the GNUnet request4/response5
service over native TCP, Unix streams where available, and the UDP DNSSTUB host. It uses the
frozen borrowed Resolver core, complete DNS parser and explicit native IDNA
backend. Library code forbids unsafe Rust and GNUnet C FFI. The foreground
binary has explicit narrowly scoped activation capture and fresh-process daemon
separation; neither operation is hidden in the generic async host. The package introduces no protocol fields or official configuration keys.

`src/lib.rs`, `io.rs`, `storage.rs` and `startup.rs` form the host adapter. `../../apps/gnunet-service-resolver` contains the foreground application. `examples/fixture.rs` is a separate test executable with caller-supplied fixture
files and an owned loopback endpoint. Its arguments are not production options
or GNUnet configuration extensions. The fixture is separate from the production app and its arguments. Both packages
are integrated with workspace dependency policy and the optional SDK feature.

## Platforms and entry points

`startup::foreground_configured` runs the same bounded service engine on Linux,
macOS, Windows and FreeBSD with configured local and TCP listeners.
`foreground_tcp` explicitly selects TCP alone. Both accept `MachineInputs`
and DNS endpoints, a readiness callback and the caller's shutdown future. Windows
validates configured process identity with native token/account SIDs; Unix uses
native UID/GID observations. TCP admission always uses address ACLs, never a
substituted local process identity.

Unix startup additionally supports activation. Windows uses the shared real
AF_UNIX transport and native endpoint ACL/cleanup owner. Standard Windows
foreground startup connects the private parent byte channel and console events.
Detached startup, remaining system configuration coverage and native execution
qualification remain in [implementation status](../../IMPLEMENTATION_STATUS.md).

`foreground_listening_with_async_ready` awaits native readiness publication after
Host construction and before drive. The synchronous `foreground_listening_with_clock`
entry returns that same future directly, avoiding an extra large async frame.
Publication failure follows the same explicit Host/listener cleanup and error
retention path. Cancellation retains no detached notification task; Drop cleanup
remains best effort. Write submission and parent-observed readiness are separate
[bootstrap facts](../service-startup/README.md#windows-parent-bootstrap).

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
listeners; the foreground assembly closes BoundListeners after stopping the
host. Failed endpoint cleanup retains the original owner in
`startup::ForegroundFailure::listener_cleanup`, alongside independent drive and
host cleanup failures. Callers can downcast the returned error and retry the
remaining owner's `close`. Cancellation and Drop cleanup remain best effort.
Inherited Unix paths keep parent ownership.

## Native startup and explicit resource scope

`MachineInputs::production` samples machine inputs once. Unix reads literal
`/etc/hosts` and `/etc/resolv.conf`; Windows reads hosts from the native configured
Internet database directory (`DatabasePath`) and queries operational adapters'
DNS servers. Only an absent registry path selects the system directory's
`drivers/etc`; discovery failures stay distinct from hosts-file read failures. Native server tuples retain their ports, IPv6 scopes and first-attempt
order. File reads have a caller-selected byte ceiling (16 MiB in the Unix binary)
and grow backing geometrically within that ceiling. `MachineDiagnostic` retains
the actual source and read/query/resource error, with that failed input empty.
No machine file is written and no system NSS/DNS lookup handles service requests.
Windows obtains the primary DNS domain separately; an empty primary domain uses
the first nonempty operational-adapter suffix. Domain errors have a distinct
`MachineSource::DnsDomain` diagnostic and leave valid server inputs available.
`MachineInputs::search_domain` installs this single domain after literal file
loading. Explicit embedding inputs do not trigger discovery. Native
qualification is tracked in the [implementation status](../../IMPLEMENTATION_STATUS.md).

`Host::set_search_domain` uses the pure core's existing GNUnet expansion rule:
original cache first, append the configured domain only to a name without dots,
then preserve the original lookup, family sequence, stub token and deadline.
C-string prefix and source name bounds remain unchanged. None clears an explicitly
installed domain; `MachineInputs::search_domain = None` instead leaves the file's
domain unchanged. Changes after client admission or with pending effects are
refused, preventing a new domain from relabeling live queries or cached results.
Windows search-list, devolution and NRPT policies are outside this single-domain
profile.
Parsed Unix nameserver addresses use port 53. Invalid IP syntax is
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
Ready follows Host construction/loading. Original construction/drive/Ready error
and independent host/node cleanup failures are retained together; an actual
physical report is present only after host construction. The foreground embedding delegates to that same implementation with
native UTC and requires an already prepared identity. Linux, Darwin, FreeBSD and Windows family selection is explicit; other native
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
