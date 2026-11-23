# Official Resolver native host

This workspace adapter executes the GNUnet request4/response5
service over native TCP and Unix streams where available. It uses the borrowed
Resolver core, UDP DNSSTUB, DNS parser and explicit native IDNA backend.
Embedded hosts can select a system-policy DNS provider. Native callback code
is confined to that provider. The foreground
binary has explicit narrowly scoped activation capture and fresh-process daemon
separation; neither operation is hidden in the generic async host. The package introduces no protocol fields or official configuration keys.

[`gnunet-service-resolver`](../../apps/gnunet-service-resolver/README.md) is the
standalone application. `examples/fixture.rs` drives the same host with supplied
machine files and a loopback DNS server for interoperability checks.

## Platforms and entry points

`startup::foreground_configured` runs the same bounded service engine on Linux,
macOS, Windows and FreeBSD with configured local and TCP listeners.
`foreground_tcp` explicitly selects TCP alone. Both accept `MachineInputs`
and DNS endpoints, a readiness callback and the caller's shutdown future. Windows
validates configured process identity with native token/account SIDs; Unix uses
native UID/GID observations. TCP admission always uses address ACLs, never a
substituted local process identity.

Applications can poll `startup::serve_embedded` on their own Tokio runtime.
`EmbeddedSettings` supplies explicit configuration, one `EmbeddedDns` source
and the application's shared `RuntimeClock`. Datagram inputs carry machine
files, numeric endpoints and an optional snapshots receiver. The caller owns
readiness and shutdown. A previously
requested stop skips binding. A stop during bound startup closes the original
listeners and cancels any pending readiness future.

For live DNS, pass the receiver from `startup::upstream_updates()` in
`EmbeddedDns::Datagram::updates`. A snapshot replaces the ordered upstream
list, retires the old DNS sockets and clears dynamic DNS cache entries. An
empty snapshot disables upstream queries. Existing lookups retain their
original deadlines and get fresh DNS transactions when upstreams are available.

`EmbeddedDns::System` uses DNS-SD on macOS, the DNS Client on Windows, and
the system name service on Linux and FreeBSD. The system owns DNS policy. The
adapter sends A, AAAA and PTR results over normal
RESOLVER IPC and omits IPv6 addresses that require a scope. Each question
admits up to 32 answers. System DNS requires an unprotected socket policy.
[Apple DNS-SD](https://developer.apple.com/documentation/dnssd/dnsservicequeryrecord(_:_:_:_:_:_:_:_:)) ·
[Windows DNS Client](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsqueryex) ·
[Linux getaddrinfo](https://man7.org/linux/man-pages/man3/getaddrinfo.3.html) ·
[FreeBSD getaddrinfo](https://man.freebsd.org/cgi/man.cgi?query=getaddrinfo&sektion=3)

Linux and FreeBSD run each blocking name-service query in a child under the
node's service identity. `SystemDns::for_worker` selects a trusted absolute executable.
That executable dispatches `SYSTEM_DNS_WORKER_ARGUMENT` to
`serve_system_dns_worker` before starting its runtime. `gnunet-node` supplies
this entry itself. Private pipes carry one bounded RESOLVER request and its
responses. The original parent-death signal covers process exit.

Timeout, IPC disconnect and shutdown request cancellation. Native admission
allows 16 concurrent Unix workers or 128 native operations on macOS and
Windows. The backend holds capacity until the original child is reaped or
the native callback owner retires.

Unix startup additionally supports activation. Windows uses the shared real
AF_UNIX transport and native endpoint ACL/cleanup owner. Standard Windows
foreground startup connects the private parent byte channel and console events.
Detached startup, remaining system configuration coverage and native execution
qualification remain in [implementation status](../../IMPLEMENTATION_STATUS.md).

`serve_standalone` uses live system DNS on macOS and Windows and the UDP pipeline
with machine files elsewhere. The `foreground_listening_with_async_ready` and
`foreground_listening_with_clock` entries use the caller's explicit datagram
inputs. All three own the finished listeners and publish readiness after backend
construction and before drive. Publication failure follows the same explicit
host/listener cleanup and error retention path. Write submission and
parent-observed readiness are separate
[bootstrap facts](../service-startup/README.md#windows-parent-bootstrap).

## Ownership and cancellation

The caller owns two fallibly allocated, initialized `Store` values and an IDNA
Workspace. `Host` takes a `Resolver` plus its equal-geometry transaction Scratch,
borrows the IDNA backend, and owns streams, the selected DNS source and bounded
queues. A core output view
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
all client streams and retires the selected DNS backend before releasing Stop.
The caller owns
listeners; the foreground assembly closes BoundListeners after stopping the
host. Failed endpoint cleanup retains the original owner in
`startup::ForegroundFailure::listener_cleanup`, alongside independent drive and
host cleanup failures. Callers can downcast the returned error and retry the
remaining owner's `close`. Cancellation and Drop cleanup remain best effort.
Inherited Unix paths keep parent ownership.

## Native startup and explicit resource scope

`MachineInputs::production` samples startup inputs for the optional datagram
backend. Unix reads literal
`/etc/hosts` and `/etc/resolv.conf`; Windows reads hosts from the native configured
Internet database directory (`DatabasePath`) and queries operational adapters'
DNS servers. Only an absent registry path selects the system directory's
`drivers/etc`; discovery failures stay distinct from hosts-file read failures. Native server tuples retain their ports, IPv6 scopes and first-attempt
order. File reads have a caller-selected byte ceiling (16 MiB in the Unix binary)
and grow backing geometrically within that ceiling. `MachineDiagnostic` retains
the actual source and read/query/resource error, with that failed input empty.
The datagram source reads these files without modifying them.
Windows obtains the primary DNS domain separately; an empty primary domain uses
the first nonempty operational-adapter suffix. Domain errors have a distinct
`MachineSource::DnsDomain` diagnostic and leave valid server inputs available.
`MachineInputs::search_domain` installs this single domain after literal file
loading. Neither explicit embedding inputs nor the system DNS backend triggers
datagram input discovery.

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
uses standard SERVICE options and explicit daemon readiness. Unix startup retains
activation and prebound TCP before applying `USERNAME`, then finishes local
listeners and initializes DNS as that account. Unix admission uses shared kernel
UID-first/GID-or-group checks; absent flags are false. Generic async embedding
verifies a configured account against real/effective IDs without changing them.

`Host::set_runtime_clock` installs one RuntimeClock Arc and exclusive
subscription immediately after Host::new, before machine data/endpoints/admission/drive. All UTC cache/receive evaluation uses this original source; native epoch,
entropy functions and original scheduling deadlines are unchanged. Once data or
lookup work starts the source cannot be replaced. Logical changes are polled in
the drive waiter, alongside native I/O/timers. Clock errors and all other
post-construction failures still take the same Immediate physical shutdown;
subscription retirement and client/DNS cleanup require no new clock sample.
Original construction, drive or readiness errors and independent host/node
cleanup failures are retained together; an actual
physical report is present only after host construction. The foreground
embedding uses native UTC and requires an already prepared identity. The
RESOLVER service and client broker use the target SDK's native address-family
values for local IPC.

Default logical geometry is clients64/lookups128/hosts1024/buckets1025/records4096/
effects512, with two independent 8 MiB aggregate byte pools. Legal record width
is65535, independently of aggregate capacity. Host TX is256 KiB per connection,
DNS receive65535, expanded parse arena4 MiB, query slots13104 and record slots5956. All allocations are bounded/fallible; allocation metadata overhead and kernel
buffers are outside these explicit byte counts. Diagnostic counters saturate at
u64::MAX as lower bounds and cannot abort or replay a business commit.

## Development

`cargo test -p gnunet-resolver-host` covers IPC, explicit UDP inputs, upstream
replacement and cancellation. `tools/verify.py` also runs the official C client
against the Rust UDP fixture and checks native localhost resolution and Unix
listener ownership in the standalone app. The SDK feature `official-resolver`
exports `gnunet::resolver_host`; builds without the host feature retain the pure
`resolver_service` core.
