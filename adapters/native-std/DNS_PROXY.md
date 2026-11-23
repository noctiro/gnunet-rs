# Native DNS proxy

The macOS `dns-proxy` feature supplies the native provider class, original UDP
and TCP flow owners, Network.framework upstream connections and bounded callback
lifetimes. GNUnet DNS parsing and client messages remain in the
[shared DNS host](../dns-service-std/README.md).

## Provider and entry point

`provider::Controller::register` registers `GNUnetDNSProxyProvider` and reserves
its lifecycle slots and incoming-flow queue. It does not activate an extension.
The OS-launched [gnunet-dns-proxy executable](../../apps/gnunet-service-dns/macos/README.md)
enters `NEProvider.startSystemExtensionMode()` on the main thread and drives the
ordinary Rust service on one Tokio owner thread.

`Controller::poll_event` yields exclusive `StartRequest`, `AcceptedFlow` and
`StopRequest` owners. Startup supplies a bounded, absolute `GNUNET_CONFIG` path
from the original provider options. The host calls `StartRequest::ready` after
its configured listeners, gateway and sources exist. Rejection or an unfulfilled
startup owner reports failure.

The bridge retains each incoming UDP or TCP flow before returning YES. Its
noncloneable loan has one `adopt` operation; dropping an unadopted loan closes its
directions. `Session::lease` bounds native resource groups before construction.
Callbacks retain that same lease, so dropping a host owner cannot acknowledge
provider stop while its SDK loans remain live. `StopRequest::poll_complete`
requires closed admission and all original leases released. Dropping a stop
obligation requests cancellation without invoking its void success completion.

## Containing-application management

The separate `dns-proxy-control` feature adds application and management APIs;
the provider's `dns-proxy` feature does not link AppKit or SystemExtensions.

`application::Application` validates the containing APPL bundle and drives one
management owner on the main thread inside the real AppKit event loop. A private
common-mode timer performs bounded polling; completion stops the application
loop with an original preallocated wake event.

`extension::Operation` submits explicit activation or deactivation requests.
Progress distinguishes user approval, replacement decisions and final completed
or after-reboot results. Replacement is refused by default; an explicit upgrade
policy checks the original bundle identities and exact proposed version.
The native SDK independently enforces signing/team and deployment policy.
The fixed request registry includes operations whose Rust poll owner was
dropped. Those original request/delegate loans retire only after the terminal
callback and deferred main-queue disposal. A wait deadline grants no cancellation
or rollback authority.

`management::Manager` exclusively owns the process's native DNS preference
manager, including callbacks still retiring after owner drop. Load, apply,
disable and removal are serialized. Mutations require freshly loaded preferences
and an exact provider identity; native stale-configuration errors are retained
without overwrite retries. Disable preserves the original provider protocol.
A malformed owned configuration path is reported separately so explicit repair
or removal remains possible. Save success requires reload before observing the
next snapshot; saved enablement is distinct from actual provider readiness.

The [containing application](../../apps/gnunet-service-dns/macos/README.md#containing-application)
composes these operations. No module registers, signs or activates a provider
merely by being linked.

## Flow availability and endpoints

Flow adoption requires macOS 15+ modern selectors and checks the native class
before use. `UdpFlow` and `TcpFlow` remain on their adopting thread; neither is
`Send` or `Sync`. Callback contexts retain independent thread-safe native owners.
The unsafe raw-object adoption methods remain available for custom integration;
the provider's safe accepted-flow loans establish their exclusive ownership.

Opening supplies the original `localFlowEndpoint` when present. UDP observes
the same flow again after successful opening and retains any local endpoint
the SDK supplies then. Valid native endpoints retain their original
`nw_endpoint_t`, including hostname, Bonjour and URL values.
Numeric link-local and legacy site-local IPv6 retain their explicit native zone
and require the original local endpoint. Numeric endpoints with the same scoped
address class must agree on that zone. A site zone is never converted to an
interface index. Multicast cannot select a local endpoint or TCP peer. UDP
reply sources and fixed resolver peers cannot be multicast, unspecified or
limited broadcast. IPv4-mapped
IPv6 receives the same IPv4 eligibility checks without replacing its original
SDK representation. Local wildcards remain permitted. These checks retain SDK
ownership without establishing runtime route qualification or a multicast relay.

## UDP operations

| Admission | Observation | Contract |
| --- | --- | --- |
| `begin_open` | `poll_open` | Open this original flow once. |
| `begin_read(ReadLimits)` | `poll_read` | One bounded batch or `Read::End`. |
| `begin_write(Vec<u8>, ReplyEndpoint)` | `poll_write` | One datagram through its original flow and endpoint. |
| `request_close` | `poll_retirement` | Request both directions closed and observe callback disposal. |

`Datagram` pairs zeroizing DNS bytes with a noncloneable `ReplyEndpoint`.
`FlowId` is process-unique and never reused; equal network tuples or DNS IDs do
not share authority. A foreign endpoint is refused before write submission.
`WriteRejected::into_parts` returns the cause, bytes and original endpoint;
transferring a `Vec` also transfers responsibility for wiping it.

`ReadLimits` bounds datagram count, individual size and retained DNS allocation
capacity per completion. DNS bodies are at most 65519 bytes, matching the
GNUnet interception IPC envelope. Accepted data and explicit refusal counts are
returned together. SDK arrays are borrowed only during their callback; native
SDK storage remains separate from the Rust allocation bounds.

The host admits these datagrams to the same `Gateway` and PRE/POST engine used
by packet sources. No IP envelope or additional GNUnet wire field is generated.

## Native multicast exchange

`begin_read_with_multicast` adds `ReadDatagram::Multicast` to the bounded read
result. The request retains the exact group destination and captured bytes.
`begin_multicast` accepts it only on its original flow and requires the
original bound SDK interface and a concrete local unicast address and port.
Explicit IPv6 link zones must match that original interface's observed index;
site and wider zones are never interpreted as interface indices.
It starts one Network.framework group and submits the original datagram once
after native readiness.

`poll_multicast` yields the native send result, replies and retirement. A
single receive slot bounds retained data. Each reply carries the original
message's unicast sender after the SDK-supplied local endpoint, family, port
and zone checks. The caller supplies DNS reply correlation and the exchange
deadline. Cancellation retires the group state and receive registrations and
any submitted send. The retirement receipt retains a successful native send
even if it arrives during cancellation. Flow closure also cancels its group.

The ordinary DNS gateway uses the unicast read path. The provider exposes a
separate [port 53 relay setting](../../apps/gnunet-service-dns/macos/README.md#configuration).
Multicast delivery and recursion exclusion require signed provider qualification.

## TCP operations and upstreams

`TcpFlow` has one open, read and write operation slot. `begin_read(maximum)`
reserves a bounded Rust buffer; `TcpRead` returns owned bytes or EOF.
`begin_write(&[u8])` makes an immutable native copy before submission, allowing
the host to reuse its Rust buffer after completion. `close_read` and
`close_write` preserve independent half-close directions.

The SDK's `readData` operation accepts no maximum-length argument. A completion
larger than the reserved bound fails explicitly; it is never truncated into a
successful stream read. The maximum configurable Rust chunk is 1 MiB. The
host's bounded TCP relay preserves byte order, EOF and errors without entering
the GNUnet UDP interception phases.

`Connection::tcp_in_provider` retains the flow's original remote endpoint and
binds to that exact `FlowId`. It copies the flow metadata to the native
parameters and preserves an application interface binding with the original
`nw_interface_t`. Missing required interface ownership is a refusal. An unbound
flow does not acquire a new interface binding.

`Connection::peer_addr` is a fallible numeric observation; an opaque endpoint
does not become invalid because that observation is unavailable.
`matches_tcp_flow` checks original construction provenance independently from
numeric address equality. `udp_in_provider` uses an explicit numeric unicast
resolver endpoint with a nonzero port and the original IPv6 zone where
required. Both constructors require a lease reserved
before native startup and use Network.framework. Each connection has one bounded
send and receive in flight.
TCP FIN shares the send slot; received bytes precede any accompanying error.
Cancellation retains these operations until the final cancelled state and
callback disposal. The provider route uses these connections, rather than
assuming BSD sockets are excluded from recursive capture.

`Connection` exposes native state and completion observations without extending
deadlines. The DNS host applies fixed readiness/send bounds and retains callback
loans after expiry; a timeout does not establish whether native acceptance later
occurred.

## Completion and retirement

Operations reserve one-shot publication slots before submission. Callback
publication moves an owned result into its reserved slot and wakes the current
poll owner. Results become observable only after the original callback block
releases its arguments. Duplicate invocation grants no additional completion;
panics are contained at the native boundary.

A successful flow write callback means acceptance into the associated socket's
receive buffer, not application consumption. Immutable `NSData` arguments stay
retained through callback disposal. Retained Rust DNS allocations zeroize when
released; native SDK allocations have their own lifetime.

After close, poll outstanding open/read/write results before `poll_retirement`.
Flow retirement does not consume those results for the caller. Connection
retirement drains abandoned results after cancellation. Neither a cancelled wait
nor `Drop` replays bytes or frees SDK-borrowed storage. Void SDK close methods
provide no close acknowledgement.

See [native backend qualification](../dns-service-std/NATIVE_BACKENDS.md#qualification)
for deployment, upstream-recursion and original-zone acceptance requirements.
