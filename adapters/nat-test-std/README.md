# GNUnet NAT tests and commands

`gnunet-nat-test-host` provides caller-driven reachability tests and the shared
implementation of `gnunet-nat` and `gnunet-nat-auto` on Linux, macOS, FreeBSD and
Windows. It uses the official NAT registration, autoconfiguration and test
messages through the shared CLIENT and Resolver adapters.

## Test interface

`Test::start(instance, sources, request, limits)` binds the challenge listener
before registering its endpoint. `Test::from_configuration` reads the selected
section's `PORT` and protocol and freezes the NAT and test-server endpoints
together. Drive `Test::poll` or `drive` and the process Resolver in an I/O-enabled
Tokio runtime. Construction alone does not establish reachability.

Every IPv4 address callback gets a dedicated test-server connection and the
official 16-byte `NAT_TEST` request. The active test format is IPv4-only; IPv6
registration hints remain valid without creating an alternative test message.
An advertised zero port in an ordinary TCP/UDP test uses the bound local port
as the attempted target, without claiming that it is an observed mapping.

A received result requires a complete local request write, a matching two-byte
challenge, the original live registration epoch and address allocation, and
input from the original listener or reversal callback. TCP retains partial
reads; UDP rejects oversized challenge payloads. Removed addresses retain bounded
challenge tombstones. The challenge and ICMP reversal are unauthenticated:
`Observation` describes a network-path observation, never a peer identity.

`Outcome` distinguishes received, timeout, cancellation and failure. Canonical
clock failure remains a failure even when its cause is `Deadline`. Original
canonical and monotonic deadlines never renew. Dropping a borrowed drive future
retains partial progress; cancellation or dropping the owner closes its original
connections, streams and listeners without retracting remote effects.

## Reversal tests

For `PORT = 0`, the caller binds an ephemeral TCP/UDP endpoint and registers its
wildcard address. Only the original NAT reversal callback can complete this test;
ordinary challenge traffic cannot become an ICMP traversal result.

The selected official C test leaves its challenge at zero and registers no
bindings, which conflicts with its helper's nonzero-port requirement and NATed
registration policy. Rust sends the unchanged official reversal format with a
nonzero challenge and an actual binding. It does not emulate these C defects or
fall back to a private message.

## Commands and configuration

The optional `program` feature supplies `cli::scheduled` with one PROGRAM task,
canonical clock, explicitly driven Resolver, selected Logger and original native
stop source. Entries capture `ClientStartup` before other native resources.
Action owners are dropped before Resolver disconnect; cancellation, scheduling,
disconnect and diagnostic failures remain independently reportable.

- `gnunet-nat` accepts `--in/-i`, `--remote/-r`, `--section/-S`, `--stun/-s`,
  `--tcp/-t`, `--udp/-u` and `--watch/-W`. STUN uses the same bound UDP socket and
  forwards only matching current-epoch responses. Reversal intent is one-shot;
  reconnect does not replay it. Monitoring uses explicit fresh registration
  leases and preserves every queued write's original bounds.
- `gnunet-nat-auto` accepts `--auto/-a`, `--section/-S`, `--tcp/-t`, `--udp/-u`
  and `--write/-w`. It prints actual status/type and proposed configuration.
  `--write` publishes only a successful proposal's NAT values through the shared
  configuration writer. A proposal does not establish connectivity or reconfigure
  a running service.

Both commands accept shared PROGRAM options. TCP and UDP are mutually exclusive.
Missing actions and unexpected completion are errors. Process exit zero and the
PROGRAM result are distinct. See the [command](../../apps/gnunet-nat/README.md)
and [autoconfiguration](../../apps/gnunet-nat-auto/README.md) examples.

`[nat-rust]` keys `TEST_TIMEOUT`, `SEND_TIMEOUT`, `SESSION_LIFETIME` and
`STUN_REQUEST_TIMEOUT` bound work; durations must be finite and nonzero.
`[nat] STUN_SERVERS` and `STUN_FREQUENCY` select STUN endpoints and refresh timing.
Native sockets use exclusive binding and suppress UDP connection-reset receives
on Windows. Unix TCP listeners enable address reuse for restart.

## Related interfaces

The SDK exports `clients::nat_test` separately from registration and query API
`clients::nat`. Primitive test/client builds do not require IGD providers or HTTP.
Full services select the [NAT provider feature](../nat-std/README.md).
The independent [burst utility](../nat-burst-std/README.md) supplies port scanning.
Runtime and interoperability qualification is tracked in the central
[implementation status](../../IMPLEMENTATION_STATUS.md).
