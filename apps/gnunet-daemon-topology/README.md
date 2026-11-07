# gnunet-daemon-topology

Foreground `gnunet-daemon-topology -c <config>` uses shared PROGRAM configuration/logging, process RuntimeClock, configured topology USERNAME/group transition, the process Resolver broker, native clients and original parent/signal control. No IPC listener, database, private key source, helper process or hidden task is introduced. Inherited listener/readiness descriptors are explicitly refused and physically released under the shared early ownership API; a PROGRAM daemon does not claim to bind a SERVICE listener. Actual parent signal ownership is retained.

The official `[topology] TARGET-CONNECTION-COUNT` defaults to16. Explicit `[core]`, `[pils]`, `[peerstore]`, `[transport]` endpoints are required through the ordinary configuration/Resolver path. `[topology-rust]` selects bounded memory/time limits and exact HELLO/CORE profiles; see example.conf. Default HELLO signature coverage is MetadataOnly. Transport hints and gossip do not authenticate any advertised address.

Node-wide `[PILS] PROFILE` selects the local PILS client semantics;
optional `[topology-rust] PILS_PROFILE` must agree. The local typed profile is
never reconstructed from remote HELLO coverage. `HELLO_PROFILE` is a separate
explicit remote verification policy, defaulting to the selected node profile's
coverage. It may be `reference029` or `deterministic` independently of the local
derivation. `CORE_CLASS_ORDER` still describes its own IPC ABI. No verifier
fallback or source/identity replacement is inferred from these choices.

READY is emitted only after CORE initialization, verified PILS identity, initial PEERSTORE monitor SYNC and TRANSPORT application attachment. None is inferred from successful construction or elapsed time. The original finite startup deadline closes all sources if these observations do not complete. Later source-loss events revoke the relevant current readiness state; an earlier READY line remains a historical observation. SIGINT/SIGTERM, parent stop and original daemon-lifetime expiry physically close all original native sources; original write/store outcomes and independent cleanup failures are reported. STOPPED does not imply remote gossip delivery or STORE success.

This production source passed strict affected compilation. Two independent pure metadata policy models passed in the core. Full-node/peer-underlay and official C interoperability remain unqualified.

The pinned entry is GNUNET_PROGRAM_run with an empty component-specific option table; topology.conf sets NOARMBIND=YES. TOPOLOGY therefore adds no SERVICE listener, SERVICE -d or daemon-ready byte contract. Inherited SERVICE listener deployment is not a required missing TOPOLOGY capability. Actual provider, statistics, failure and cleanup diagnostics use the same PROGRAM-selected Logger and SharedClock, including -L/-l policy. The first diagnostic error wakes the original driver, closes its sources, and is retained independently alongside any original business or cleanup error. Original READY/STOPPED stdout observations remain explicit flushed output rather than log messages.
