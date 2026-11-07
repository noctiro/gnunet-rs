# ARM daemon std host foundation

The workspace host uses the pinned 121-obligation source inventory in
`crates/gnunet-arm-service-core/source-inventory.json`. It implements registry/config
selection and managed-listener ownership/readiness. Managed process spawn/reap,
daemon IPC and timers still require their host integration and validation.

Official anchors: gnunet-service-arm.c setup_service1897 registry/BINARY/category/CONFIG/PIPECONTROL/IMMEDIATE_START/NOARMBIND/START_ON_DEMAND and reversed iteration; get_server_addresses342..661 native endpoint/probe rules; create_listen_socket995..1112 reuse/v6only/backlog5/permission flags; accept_connection975 only readiness, never accept; start_process745 disarms all tasks before inherited listener mapping; shutdown1500 closes every parent listener before any TERM. Generic BoundListeners::bind cannot be substituted wholesale: its port/error/UID policy and private API differ. Reuse low-level bind_private/CreatedPath/private_parents and safe socket2 instead.

The shared `gnunet-service-runtime::readiness` module uses Tokio1.54.1's
native constructor once in a stable opaque OwnedFd wrapper, with no
get_mut/replacement. Host body forbids unsafe. Poll0 with locked nix0.31.3 confirms
level readiness without accept/read. Cached hints returning WouldBlock are cleared. HUP/ERR/NVAL are explicitly classified. into_owned deregisters first. Drive
cancellation retains the owner, logical Arm and leased core authority.

ManagedListener stores opaque readiness/socket owner before an optional CreatedPath guard, closing FD before inode removal. Inherited sockets never acquire path guards. Core ListenerId/ReadinessId and native original owner are mapped one-to-one; Arm installs one logical watcher, Disarm removes it without accepting, Close actually consumes the parent listener and then acknowledges. Poll only logically armed watchers. A readiness pulse stores the exact current core ReadinessId before returning/awaiting so cancellation cannot lose a consumed event. Parent listener remains available for child inheritance; after child consumes backlog, cached stale readiness must not trigger a new process.

Minimal future process reuse: typed NativeCommand needs executable filename separate from argv0 (official SIMPLE), exact argv/environment, borrowed fd mappings/control writer, fork-admission receipt and independent original-child wait authority. Current ARM-self LocalLauncher does not provide this generic contract. No private native code is copied into this host; parent chose future shared process-port review.

Registry owns raw byte names/binaries/config/command plans and returns borrowed official SourceSpec views. It retains all registered eligible sections even when no listeners or address failures, preserves original ordering/case, and separates partial endpoint failures from registry capacity rejection. No private resolver, DNS frontend or extra UID authentication is introduced. Tests use only owned local resources; ordinary names resolved by native helpers remain an explicit bounded host boundary, no public DNS in tests.
