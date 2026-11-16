# gnunet-daemon-topology

Maintains peer connections and exchanges public HELLO announcements through
the configured CORE, PILS, PEERSTORE and TRANSPORT services. The executable
uses the shared native PROGRAM entry on Linux, macOS, FreeBSD and Windows.
Protocol policy lives in [gnunet-topology](../../crates/gnunet-topology/);
native source ownership lives in [gnunet-topology-host](../../adapters/topology-std/).

## Configuration and invocation

```sh
gnunet-daemon-topology -c gnunet.conf
```

Configure `[core]`, `[pils]`, `[peerstore]`, `[transport]` and `[statistics]`
endpoints through the ordinary configuration and Resolver path. The official
`[topology] TARGET-CONNECTION-COUNT` defaults to 16. See [example.conf](example.conf)
for bounded memory, queue, lifetime and startup settings.

Node-wide `[PILS] PROFILE` selects local identity semantics. An optional
`[topology-rust] PILS_PROFILE` must agree. `HELLO_PROFILE` independently selects
remote verification coverage (`reference029` or `deterministic`); its default
inherits the node's selected coverage. `CORE_CLASS_ORDER` selects the CORE IPC
ABI. Metadata-only signatures do not authenticate advertised addresses.

## Startup and shutdown

The daemon uses PROGRAM configuration and `-L`/`-l` logging. Unix applies the
configured identity before creating the reactor; Windows verifies the actual
process token. Original parent control and native termination subscriptions
remain owned throughout execution. TOPOLOGY has no SERVICE listener, detach
option or SERVICE readiness acknowledgement. Inherited SERVICE resources are
refused and released by shared client startup.

`READY topology` requires actual CORE initialization, verified PILS identity,
initial PEERSTORE monitor SYNC and TRANSPORT application attachment before the
original startup deadline. Source loss revokes the corresponding current state.
An earlier READY line does not establish continued availability.

SIGINT/SIGTERM, native parent stop, diagnostic failure and daemon expiry retire
the original protocol sources. Statistics then receive one bounded final drain,
and the original Resolver is closed. Construction failure and cancellation use
the same cleanup owners. `STOPPED` does not establish remote delivery, STORE
success or zero remaining CORE network connections.

## Statistics and errors

The shared STATISTICS producer exports `# peers connected`,
`# connect requests issued to ATS`, `# HELLO messages received` and
`# HELLO messages gossipped` under subsystem `topology`. The connection count is
the last actual CORE observation. Counter deltas are never replayed after an
uncertain write or source loss. Final shutdown grants the original producer
five seconds; unconfirmed mutations remain explicit in its report.

Provider, Resolver, statistics, output and cleanup errors retain independent
causes through the selected logger. Native errors expose their typed sources.
See the central [open work](../../IMPLEMENTATION_STATUS.md) for remaining
interoperability and platform qualification.
