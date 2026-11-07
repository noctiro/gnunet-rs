# Official EXIT forwarding core

This independently callable Rust core implements the pinned v0.29.1 EXIT raw-IP
forwarding boundary. Actual native TUN/CADET/DNS IO remains an explicit result
port. No FFI, C process wrapper, private wire field, private key, implicit runtime,
thread, clock, random generator or network activity exists in this crate.

The active reference is `src/service/exit/gnunet-daemon-exit.c` and `exit.h` at
commit `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`. EXIT forwards TCP, UDP and
ICMP by building raw IP packets through a TUN helper. The endpoint TCP stack
owns sequence processing, retransmission, congestion control and connection
acceptance. Rust follows that boundary.

## Layer and source dependencies

Default=[] provides noalloc policy and caller-entropy NAT routines. Explicit
alloc enables the bounded Engine and immutable whole-packet/message ownership. All IP parsing, header building, checksums, same-family rewriting, supported
ICMP type translation and truncated ICMP quote parsing are consumed from the
shared gnunet-vpn::packet module. The VPN/EXIT peer codec is the shared
gnunet-wire::official::vpn::PeerMessage. No EXIT-private replacement is invented.

## forwarding behavior

Engine::attached/tun_attached register the native adapter's successful
source/device attachment; no socket or device is inferred from the registration. An accepted channel is bound by accept to that Source, native peer
metadata and the Internet-family/service/DNS CADET port. Handles contain
private Rc identity and checked generations; numeric values are diagnostic only. A new attachment cannot replay an old source's payload or adopt its stale token.

Internet TCP-start/UDP/ICMP requests select an allowed target and allocate a
collision-checked six-tuple using explicit caller entropy inside the configured
TUN subnet. Source ports use the reference32768..61000 exclusive range,
or the original explicit UDP source port. ICMP ignores ports as in C. Configured
service targets remain pinned to their address/protocol/port; a peer-supplied
service destination field cannot retarget the service. Existing flows preserve
their tuple instead of changing destination behind an old hash-table entry.

A configured service hash may contain one TCP_REDIRECTS target and one
UDP_REDIRECTS target with different endpoints. Engine construction rejects
same-hash+same-protocol duplicates, including entries with conflicting targets. The first official TcpService/UdpService message selects the matching
transport entry; it never takes whichever same-hash configuration row came first. The native provider binds the common official CADET hash only once; no extra port
or protocol tag is invented. Once a flow has a tuple, its target/protocol/endpoint
remain pinned, and a conflicting transport message requests original channel
closure instead of rebinding it. Existing TCP/UDP service ICMP uses the tuple's
original transport to select its endpoint. An initial ICMP service request has no
TCP/UDP discriminator, so a shared two-target hash is rejected as ambiguous;
single-target service ICMP behavior is preserved.

The core creates IPv4/IPv6 packets and transport checksums. TCP raw header,
sequence/acknowledgment, flags, options and payload are preserved while NAT ports
and checksums are rewritten. UDP length includes its8-byte header. ICMP echo
payload is retained; supported error messages omit the unusable quoted packet
on GNUnet wire and reconstruct IP+8 according to the official EXIT contract. This quote synthesis is an explicit reference requirement, not a fabricated
peer response or network acceptance. Cross-family local-service ICMP uses only
the reference's supported type mappings, including explicit refusal for mappings
C declares impossible.

from_tun accepts only complete raw packets from the exact original TUN,
validates checksums, and matches full tuples. TCP return messages mask source/
destination ports and checksum to zero; UDP_REPLY ports0 preserve the VPN's
original tuple. ICMP echo returns its payload. ICMP errors use their truncated
inner IP+8 tuple to find the original flow, including router errors whose
outer source differs from the remote endpoint, then strip the quote as required
by the wire contract. Addresses/families/protocols cannot silently cross a flow.

TCP lifecycle metadata is observational: local packet construction/writing never
sets established. Only a matching TUN SYN+ACK with the original SYN's
expected acknowledgment records that observed handshake. FIN/RST are observed
without substituting a private TCP implementation or prematurely declaring all
original IO closed.

DNS193/194 is optional and has an explicit external DNS/socket request
port. A bounded query receives an entropy-derived unique transaction ID and an
original Dns job/absolute deadline. dns_admitted grants no write receipt;
dns_written is required before its original processing receipt becomes ready. Only an response supplied by the original selected socket/server operation
with matching transaction/QR restores the client's original ID. The native DNS
port must really validate socket/server ownership before calling dns_reply. No timeout manufactures NXDOMAIN or another DNS response. Cancellation retains
an issued original DNS job until dns_retired; it never creates a fake socket.

## Original output and lifecycle ports

`tun_output` and `peer_output` lend one original immutable whole packet/message
with Write, Flow and its original expiry. Reborrowing preserves the same token
and bytes. The native host must retain that scope across pending/cancelled
futures, and use its original deadline instead of restarting a relative timeout.

- tun_written means an whole packet write completed on that original
  device. peer_written means the original native MQ frame completed.
  Neither proves remote delivery or processing.
- tun_unsent/peer_unsent require the native port's proof of zero exposure.
  A Book timeout alone is insufficient. A positive short TUN write must really
  close the old device and call tun_lost with the uncertain original Write.
  An admitted MQ suffix must drain on its old socket or that socket must close.
- Processed is emitted only after forwarding write completion. The host
  aggregates original nested frame receipts for the CADET outer Delivery,
  then acknowledged is called only after the receive_done write. An issued
  processing/ACK effect retains debt through close; processing_retired is valid
  only after the native owner actually drained/closed that original action.
- Close requests original channel closure. closed records native
  channel retirement, while original leased packet/ACK/DNS debts remain until
  their own callbacks. source_lost requires physical MQ detachment first
  and retires old peer outputs without replay. tun_lost does the equivalent for
  the device, preserving OutcomeUnknown for a positive short write.
- shutdown issues original per-flow/DNS closes plus CloseSource/CloseTun. Native
  cleanup callbacks work without a healthy clock. is_quiescent requires actual
  source/device loss and all original IO/request debts settled, not a logical
  close flag or elapsed TTL.

Fresh address choice checks live and quarantined tuples. Table pressure requests
the oldest live flow close and returns WouldBlock; it does not free/rebind that
slot before retirement. After all debts settle, next_closed reports
the original result once. A bounded memory-only tuple tombstone remains until
an explicit valid clock sample starts/completes configured reuse quarantine. No stale callback can select a subsequently allocated flow generation.

`peer_ended` records an original channel destruction while its native
owner still holds earlier DATA. It uses the existing peer_closed fact without
cancelling that original forwarding work. TUN returns no longer match that
peer; a valid late DNS response is discarded without creating peer output. Only a caller-proven never-admitted borrowed peer Write can be explicitly
released; a leased native suffix keeps its exact write/loss debt. The native
adapter admits no new input on that channel, drains only its already held
packet through Processed receipts, then calls closed and retires the
gone outer locally. This is neither a processing ACK nor a new channel/source. Local close and original deadlines retain their existing cancellation policy.

All time is supplied through explicit MonoInstant. Backward samples return
TimeUncertain and do not create fake now; physical cleanup still works. Original
input/output deadlines do not reset on retries. Actual traffic can refresh idle
expiry, as genuine activity. Native adapters must additionally enforce their
own finite original physical drain/retirement budgets rather than reporting a
logical deadline as IO quiescence.

Default independent bounds are256 flow/tombstone records,512 immutable outputs/
8MiB,65535 raw-IP bytes, official64348-byte peer frames,4096 DNS bytes per flow,
64 entropy/collision attempts,300s idle,30s original input/output target and120s
NAT reuse quarantine. Allocations follow bounded content. No registry
versions are added. Service/rule slices are explicit caller-owned configuration.

## Deliberate internal corrections and limits

Active C has internal UDP host/network port/length inconsistencies, mutable
remote tuple/hash mismatches, and ICMP AF switch/lookup defects. Rust preserves
all official wire fields and platform AF profiles while building correct
IP/transport bytes and coherent tuples. C's raw IPv4/IPv6 host AF values differ
(Linuxv6=10, Darwinv6=30); AfProfile is explicit, with no invented negotiation. No undefined native struct layout or hash prefix is used as session authority.

Fragments, unsupported IP headers/types and oversized output receive actual
shared packet/resource refusals. There is no private fragmentation protocol,
synthetic success, invented random nonce or guessed endpoint acceptance. Native
provisioning/routes/TUN ownership, CADET application registration, DNS resolver
IO and regex/DHT/PILS advertisement integration remain independent platform
capabilities. This package does not reopen the stopped original DHT network,
UDP communicator crypto/collision or GNS recovery branches through another name.

## Evidence

The additive `tests/service_protocol.rs` is one pure model for same-hash TCP/UDP
endpoints, duplicate/ambiguous tuple rejection, original tuple stability, ICMP
selection and processing/write-boundary premises.
