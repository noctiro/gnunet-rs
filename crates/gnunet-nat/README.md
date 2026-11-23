# NAT protocols and registration state

Pinned official production sources: v0.29.1 commit346358e26d4dcc2dc4f51bef5d52dca29c7d8165; see the implementation public-source-inputs.json. Default no_std/noalloc supplies native-sockaddr NAT/NAT-auto/test IPC, standard STUN, and exact GNUnet ICMP traversal packets. The alloc feature supplies a bounded service registration/address owner. Native service, registration/auto clients, finite reachability-test caller, privileged helpers and ordinary commands are integrated separately in the native adapters. This pure crate does not itself perform those effects.

## Wire profiles

The listener selects the client’s native sockaddr layout (Linux, Darwin,
FreeBSD or Windows) and byte order. `RawAddress` retains original padding;
canonical address writers clear it. Frame headers and ports use network order.
`ADD_GLOBAL_ADDRESS` stores a network-order 16-bit length in a native 32-bit
field. The codec preserves the candidate bytes; a NAT provider decides which
addresses it can use. `REGISTER` accepts the bounded section bytes permitted by
C `strndup`; producers should append a NUL. There is no request ID, ACK,
UNREGISTER or CANCEL. A complete write reports local submission only.

## Registration ownership

`address::Advertised::interface` classifies a native unicast observation and
preserves its IPv6 scope. `address::AddressPolicy` projects it onto one original
registration binding without allocation. Each binding adopts its own port from
the registration when the observation has no port. An explicitly zoned IPv6
link-local binding matches observations only on its own zone. Service owners
deduplicate projected addresses and publish their effective add/remove changes.

state::Core owns original accepted Source and discovery Provider generations, registrations, effective addresses, provider snapshots, original freshness deadlines, and a finite notification queue. All snapshot changes preflight a bounded plan and downstream capacity before committed address mutation. Provider outputs require their original handle; source loss retires only its own bindings/providers/events. Native host ownership must be retained until close/cancel cleanup, must expire before draining notifications, and must stop resources on native/canonical clock failure. A provider intent or a sent packet never installs an address. STUN observations are unauthenticated server claims. Raw ICMP reversal observations are unauthenticated and remain subject to the original helper/interface/source lifetime.

The supported API provides register/snapshot/expire/provider retirement/source retirement, effective-set add/removes, scoped manual/AUTO/STUN/UPnP observations, and IPv4 reversal plans/notifications. Actual OS enumeration, Resolver DNS, UDP transactions, IGD/UPnP, helper processes, service/client MQ, PROGRAM/foreground, and NAT-auto orchestration live in gnunet-nat-host, gnunet-nat-client-host, gnunet-nat-test-host and gnunet-nat-helper-host, with separate true IO receipts. The pure endpoint plausibility predicate compares full Internet endpoints; a native client must retain raw native bytes to reproduce C GNUNET_NAT_test_address's exact sockaddr memcmp including padding.

## Corrections to internal C defects

* gnunet-service-nat.c:is_nat_v4 uses192.168/12 and172.16/16 despite RFC1918 comments. Rust uses192.168/16 and172.16/12 (plus official CGNAT and link-local ranges).
* gnunet-service-nat_stun.c:stun_get_mapped compares STUN family to AF_INET(2), while standard STUN IPv4 family is1, and its attribute loop does not honor4-byte padding. Rust parses standard family1/IPv6family2, checks padding boundaries, prefers standard XOR over Microsoft XOR/plain, and supports explicit original transaction/source/deadline correlation. Consequently the defective pinned C parser may reject a valid standards-compliant STUN response; no private malformed fallback is emitted.
* gnunet-service-nat.c:handle_stun first inserts a new STUN server then emits GNUNET_NO instead of an add. Rust's first observation adds its effective endpoint and removals happen on change/expiry. Wire notification layout is unchanged.
* nat_auto_api.c connects to nat, but the active service is nat-auto. Native adapters select nat-auto; raw IPC codec preserves all status/type values including raw0 produced by this pin's active daemon. Meson builds only gnunet-service-nat-auto.c; legacy sweeping probes are not represented as active C capabilities.
* Class PRIVATE denotes highly sensitive addresses, not RFC1918. IPv6 MAC-derived IID bytes11/12 carryFF/FE and receive the PRIVATE modifier; LAN scope and global scope are distinct.
* Helpers preserve both reversal packet variants and zero-port ordinary-probe diagnostic observations. Rust builders use a checked ones-complement checksum and native raw-length profile instead of unaligned C struct casts/UB. Helper success must require complete sends, not C's unconditional process0.

Logical clock rollback cannot renew an address expiry or revive an expired
allocation. The allocation-backed owner requires checked AtomicU64 instance
identity; the default no-allocation codecs do not require it.
