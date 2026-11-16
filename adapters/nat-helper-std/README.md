# Native NAT helpers and supervision

`gnunet-nat-helper-host::{client,server}` implement the dedicated helper
executables. Packet construction and validation stay in `gnunet_nat::icmp`;
process supervision is available separately through feature `supervisor`.

## Executable interfaces

```text
gnunet-helper-nat-client LOCAL_IP REMOTE_IP PORT
gnunet-helper-nat-server LOCAL_IP
```

Arguments are numeric IPv4 addresses and a decimal port in `1..65535`, with exact
argument counts. Raw resources are captured before argument parsing. These are
fresh, single-threaded process entries: Unix startup changes process credentials
and signal policy. They must not run inside an existing service process.

The sender builds both official 56-byte TIME_EXCEEDED variants. Both outer
packets are ICMP; one quotes ECHO and the other quotes UDP with the advertised
port in its original length field. They retain packet ID 256, dummy address
192.0.2.86, traversal port 22225 and the existing TTL fields. Both sends share one
fixed five-second budget. Each variant is independently attempted; a second
failure remains attached to the first. A short datagram is an uncertain original
outcome, never a stream suffix. Exit zero proves both complete local writes.

The observer binds UDP to `LOCAL_IP:22225` and alternates one empty UDP datagram
and one 28-byte ECHO probe every 500 ms, UDP first. Late wakes skip missed probes.
One 65535-byte receive buffer and one 22-byte endpoint line bound retained input
and output. Malformed or unrelated packets are discarded. Stdout contains only
`IPv4:PORT\n`, or `IPv4\n` for a zero-port diagnostic. Observations are
unauthenticated and establish no mapping, connectivity or peer identity.

## Unix resources and credentials

Linux, macOS and FreeBSD 12+ share the runner. Raw input and full-header output
open before an irreversible transition to the invoking real UID/GID. Linux also
clears supplementary groups when effective root, all capability sets, keepcaps
and ambient capabilities, then enables no_new_privs and verifies the IDs. BSD
uses its own ID and saved-ID contracts. A real UID-zero caller remains root.
Any transition failure closes the captured sockets before processing input.

Linux installs PDEATHSIG and rechecks its original parent. macOS and FreeBSD use
bounded same-parent polling. Stop handlers store only an atomic flag; SIGPIPE is
ignored so output failure remains observable. Controlled stop restores original
output flags and handlers, retaining independent restoration failures.

Linux and modern FreeBSD use network-order raw IPv4 lengths. macOS uses native
outer output length and normalizes only kernel-transformed receive fields before
the shared network-order parser, including XNU's quoted TIME_EXCEEDED length.
No checksum or malformed packet is repaired into success.

## Windows resources and lifetime

Windows uses protocol-specific Winsock raw ICMP sockets and network-order IPv4
headers. The invoking token must already permit raw sockets; no elevation,
set-ID emulation or alternate credentials are supplied. The UDP probe socket
uses the shared Winsock asynchronous-error policy.

The observer's protocol stdout is a private local byte pipe created by
`gnunet_native::pipe::output_pair`. Its writer includes read-attribute
rights. The supervisor retains the original overlapped reader and passes only
the synchronous writer as child stdout. The observer checks that same reader's
connection state before further work. Reader closure ends this generation;
no PID lookup or replacement process grants liveness.

Output uses nonblocking byte-pipe mode, preserving its original line cursor and
two-second target. Synchronous reader-state queries retain native errors; pipe
capacity refusal and positive native writes remain distinct. Stop or reader
closure fences new writes. Cleanup restores a live endpoint's mode; an already
closed endpoint cannot be reused. Console callbacks own only an atomic stop bit
and are explicitly removed. A kernel call cannot be promised interruptible by a
userspace deadline. Diagnostics have fixed-size formatting and use the original
stderr route; they never write protocol stdout.

These are native capabilities, not platform substitutions: raw socket access,
UDP bind, output qualification and restoration retain their actual errors.
Windows standalone observers require the qualified output pipe; ordinary shell
redirection does not provide that contract. The normal NAT supervisor prepares
it automatically. The finite sender observes console stop and its original
five-second budget; it supplies no Unix parent-death-signal claim.

## Caller-driven supervision

`supervisor::{Supervisor, Paths, Limits, Bounds}` owns original children,
line framing, generations, wait results and cleanup. Construction starts no
process or network request. Drive it under the caller's entered Tokio runtime;
no hidden runtime or forwarding task is created. Paths are explicit executable
locations, never shell commands.

Copied Bounds retain their original canonical expiry and native target. Process,
clock and protocol failures have separate typed causes. Cancellation requests
stop once and continues polling the original child. A requested kill, empty
output or retirement timeout is not a successful reap. Unknown retirement stays
in NAT's unresolved cleanup report after the bounded child slot is released.

Installation privileges and native raw-network interoperability are tracked in
[implementation status](../../IMPLEMENTATION_STATUS.md).
