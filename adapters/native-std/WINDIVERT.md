# WinDivert capture and injection

The Windows `windivert` module loads an explicitly trusted official WinDivert
2.2 DLL and opens NETWORK filters against an already installed driver. It does
not download or install a provider. `Driver::load` is unsafe because the caller
certifies native code, dependencies, exact C ABI and thread-safe destruction.
The immutable resolved export table remains owned through native completion.

## Native operations and ownership

`Driver::open` validates queue controls, opens with `WINDIVERT_FLAG_NO_INSTALL`,
checks the driver version and applies the selected limits. Defaults are 128
queued packets, 1 MiB and 1000 ms. The driver's initial default queue limits apply
between native open and parameter configuration. `OpenFailure` retains both
setup failure and an independent failure to close an already opened filter.
Complete bounded interface facts and their native clock sample are prepared
before opening the filter.

A `Session` admits one receive and one injection concurrently. Each `Request`
owns a stable packet allocation, address record, OVERLAPPED, event and original
session reference. A native one-shot threadpool wait holds an independent
reference until the original event establishes I/O completion. No blocking
receive thread, per-packet worker thread or detached Rust reaper queue is used.

Canceling or dropping a request requests cancellation; it does not prove
completion. Original loan storage and the provider remain live until native
completion. Completion releases its directional credit before waking the
caller. A provider that never completes can retain that original loan; callers
must keep teardown deadlines and unconfirmed retirement separate.

## Packet metadata and injection

A receive returns raw IP bytes and opaque original metadata. At receive
completion, the packet's WinDivert timestamp selects an immutable interface view
from at most two complete observations. Both use the native
`QueryPerformanceCounter` clock. A newly observed interface is eligible only for
captures strictly after that view's clock sample; older captures use the previous
view. An expired view, unknown index or exact observation boundary refuses that
capture. Unchanged scans preserve the previous interval. Failed refreshes keep
both old views intact, and a refused capture cannot acquire a later identity.

`CapturedAddress::reply` rechecks the frozen identity before returning a
`ReplyAddress`. It preserves interface/subinterface indices and the original
session identity.
Replies reverse direction except for WinDivert's outbound-only loopback profile.
Inbound routes retain an observed LUID, GUID, interface index and the calling
thread's original compartment. `Session::send` rechecks that observation before native
admission; it never substitutes the current interface behind a reused index.
Outbound routes retain the original compartment, since WinDivert ignores their
interface indices. Wintun shares the same native identity observation primitive,
while retaining its separate adapter ownership and permanent retirement gate.

`Session::refresh_routes` prepares and validates a complete snapshot before
publishing it under the shared observation lock. Old allocations are released
outside that lock. The DNS source refreshes once per second and expedites a scan
after a route refusal, with at least 100 ms between attempts. Refresh does not
replace the filter, upstream socket reservations or original overlapped loans.
Refresh failures have their own diagnostic event and counter; they do not count
as packet refusals or clear the last complete observation.

Injection through another session is refused even if Windows reused a numeric
handle. The caller supplies a complete packet with valid checksums. A successful
injection receipt requires the complete original byte length. An
`InjectionLengthError` records a violated extent and requires source retirement;
short or failed injections are never continued as a suffix or replayed.

The provider's NETWORK metadata contains indices and a timestamp, without an
interface LUID/GUID or packet compartment ID. Identity observation does not lock
the kernel interface or prove uninterrupted identity between snapshots. Driver
classification and observation races, transient replacements, final-check to
injection changes, subinterface replacement and non-default compartment behavior
remain native qualification work.

## Shutdown and uncertain exposure

Shutdown, cancellation, filter close and I/O completion are independent
observations. The original handle is removed from admission under a mutex
before its one close attempt; later callbacks cannot operate on a numerically
reused handle. If close won the race with completion, injection exposure may
remain unknown. No API turns that uncertainty into an unsent-packet claim.

The DNS host isolates a refused original route to its own query. It also
cancels an expired injection once and keeps its original loan until completion.
Retirement is bounded by five seconds after the first cancellation or original
hard deadline, whichever is earlier; failure
to retire closes the source. Completion is polled before canonical-clock work,
so an unavailable logical clock cannot strand an already admitted native loan.
A whole injection observed after expiry is reported as accepted late; an error
retains unknown exposure and its actual completion cause. Neither is replayed.

The DNS integration holds exclusive original upstream-port reservations until
the filter is closed. An unconfirmed filter close quarantines that finite port
lease until process exit, including failure during post-open setup. No retry or
replacement filter is started by that owner. See the [DNS host](../dns-service-std/README.md)
and [service configuration](../../apps/gnunet-service-dns/README.md).

## Reference interfaces

The boundary follows the official [WinDivert header](https://github.com/basil00/WinDivert/blob/master/include/windivert.h)
and [WinDivert API documentation](https://reqrypt.org/windivert-doc.html).
Native driver execution and platform qualification remain tracked in
[implementation status](../../IMPLEMENTATION_STATUS.md).
