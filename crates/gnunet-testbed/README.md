# Active official TESTBED resource core

Pinned v0.29.1 commit346358e26d4dcc2dc4f51bef5d52dca29c7d8165 builds
`testbed.c` as libgnunettestbed. Its production public header has only system
create/create-with-portrange/destroy, reserve/release-port and configuration-create. There is no active TESTBED controller daemon, local/remote controller IPC,
operation/cancel/reconnect wire, host/peer lifecycle or topology protocol in this
release. A residual peer_destroy comment is not an exported built implementation. The testing interpreter wrapper only creates/destroys the same system and exposes
its handle as a trait. Rust directly exposes the owned resource handle instead
of copying the C command/trait dispatcher or using dlopen/FFI.

This no_std/noalloc core owns an 8KiB unavailable/reserved-port bitmap plus
caller-fixed PortSlot metadata. An explicit caller Instance uses checked local
allocation IDs, with no hidden globals/Atomic64 requirement. Probe, Reservation
and PathId retain original domain/system/serial generations. Busy candidates
remain excluded for this original system; an exact logical release may make a
reserved port available again. Stale copies cannot release a later reservation
of the same port or a replacement system's scope. Path numbers never recycle;
the native owner must actually persist the high-water before exposing a path.

Availability is an explicit provider result, not successful socket behavior
invented by the core. Logical close invalidates tokens and frees caller slots;
it is not native removal, process stop or peer readiness. The native host does
bind probes and explicit filesystem effects. No private protocol exists.

One public integer model source covers original probe completion/cancel, stale
release, exact inclusive/exclusive range, path counters and replacement scope.
