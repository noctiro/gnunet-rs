# Explicit live CLIENT configuration

This is a reviewed implementation candidate, not an ARM owner completion report.
The formal M9 baseline is source cd7835f03c66e6393fb594182f724a2c28df7b11a90a966a3b701451bb415fe0.
The original snapshot constructors remain available. The live constructors are
`ClientHost::connect_live` and `MonitorHost::start_live`; both take distinct
caller-owned `LiveConfiguration` service and resolver contexts.

`LiveConfiguration::replace` synchronously swaps one coherent Configuration. It
opens no socket, invokes no callback, schedules no retry and wakes no drive.
Existing attempts, stream owners, partial RX/TX cursors, epochs, operation IDs,
callback leases and cancellation tombstones retain their original authority.
The shared `gnunet_ipc_unix::transport::Endpoint::configuration_live` validates a
new logical MQ and caches PORT/HOSTNAME then. On an even/no-TCP physical retry it
samples only current UNIXPATH. A missing/invalid Unix value disables that Unix
attempt without invalidating the already admitted MQ or changing cached TCP.
A newly created logical MQ instead validates the current whole service config.

The source read sites are util/client.c:510-576, 726-843, 1182-1245 in pinned
GNUnet revision 346358e26d4dcc2dc4f51bef5d52dca29c7d8165. Local ARM setup reads
configuration at arm_api.c:654-768, 920-1030. This host's already-declared asynchronous
setup samples the current configuration when its original StartArm effect
actually begins. Once the OS spawn outcome exists, replacement cannot repeat
spawn or change that outcome. Native C performs setup during request admission;
this implementation does not claim identical synchronous setup timing.

A nonnumeric lookup separately snapshots the explicit resolver context. This
is not a process-global PROGRAM Resolver broker. In particular, one lookup's
internal Resolver retries retain their original snapshot; shared requests,
resolver_cfg replacement while an existing Resolver MQ lives, and its complete
retry sampling are still pending. Numeric and known-loopback addresses follow
the existing official fast paths without querying Resolver.

The C local-start success path can overwrite h->mq without destroying its old
MQ. This implementation retains the already-owned original connection and queued
bytes instead of reproducing the leaked callback/UAF risk. No claim of equal
physical connection counts is made. C's canceled ARM-stop callback NULL case is
not executed as an oracle; the Rust tombstone safely suppresses callbacks and
reclaims capacity. Existing explicit safe differences remain in UPSTREAM.md.

## Direct tests

`tests/live_configuration.rs` contains four owned-socket tests: mutable
monitor config plus EOF and no invented retry; preserved old TCP with fresh Unix
path and original queued request; live replacement during genuine kernel TX
backpressure (100 full-size frames, no replay); and an original manually-polled
connection future that neither moves to the new path nor is woken by replacement.
`tests/local_start.rs` adds one child test for setup sampling and no respawn.
`tests/loopback.rs` adds eight owned-peer negative/ownership tests. These peer
fixtures are direct Rust tests, not C-client branch observations.

Normal C/R process observations are separate receipts: 36 command profiles,
Unix/TCP ClientHost/MonitorHost to the normal C ARM daemon, native mutable
monitor configuration, and the zero-managed-service Unix/new-TCP-fence read
point probe. Their original executed input hashes and limitations are retained;
none is promoted to current whole-source evidence without a fresh frozen run.
The old verify.py's M8 counts are historical and are not an M9 verifier.
