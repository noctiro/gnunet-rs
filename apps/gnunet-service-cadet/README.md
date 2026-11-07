# CADET service

```sh
gnunet-service-cadet -c official.conf
```

Application IPC supports ports, local loopback channels, source credit,
receive completion and channel retirement. The default peer backend composes
CORE, DHT and PILS with authenticated KX/ratchet and reliable channels.
`[cadet-rust] PEER_CORE=NO` selects local-only operation and rejects remote opens
and peer-management queries.

## Configuration and startup

The service accepts standard `-c`, `-d`, `-h`, `-L`, `-l` and `-v` options.
Listeners use `[cadet] UNIXPATH/PORT/BINDTO/DISABLEV6`, activation descriptors,
ACL/TOLERANT and `UNIX_MATCH_UID/GID`. UID policy takes precedence over GID.
Configured `USERNAME` is resolved before the process identity transition; inherited
endpoints are not reopened or chowned. Daemonization occurs before runtime/tasks
and signals readiness through the original child-status capability.

`[PILS] PROFILE` selects `reference029` by default or the official conditional
`deterministic` profile. A local `PILS_PROFILE` assertion must agree. The same
choice reaches observation, DH/signing and HELLO verification. Verification never
falls back to another profile.

Startup waits for verified PILS identity and, in peer mode, matching DH/signing
providers and durable monotime reservation. stdout READY and parent readiness
are emitted once after local construction; they do not promise remote connectivity.
Explicit local-only mode reports its peer backend as unavailable.

## Identity and storage

The application owner retains MQs and logical ports across healthy updates on the
original observer. Peer recovery stops old CORE, DH/signing, discovery and
TRANSPORT sources, retires affected remote operations and verifies fresh providers
before replacement. Repeated updates share the original recovery deadline.
Established local pairs and frozen output retain their original identity.
Physical observer loss remains fatal.

`PEER_MONOTIME_FILE` selects the filename stem, defaulting to
`${GNUNET_DATA_HOME}/cadet/rust-monotime`. Each full public identity has its own
`.peer-<hex>` namespace and exclusive writer lease. Returning identities reopen
their durable floor. Reservations precede reset timestamp use; uncertain writes
fence the store. Old unsuffixed internal files are not migrated.

## Resource limits

These `[cadet-rust]` settings are local resource policy:

| Key | Default | Constraint |
| --- | ---: | --- |
| CLIENTS | 16 | positive; native RX allocated only at accepted-MQ admission |
| PORTS | 128 | positive |
| CHANNELS | 128 | at least 2 for a usable own-peer pair |
| SOURCE_BUFFERS | CHANNELS | at least CHANNELS; surplus shares source capacity up to WINDOW |
| WINDOW | 4 | from 1 through 4 |
| IO_SLICE_BYTES | 65535 | positive one-syscall byte quantum |
| LOOP_PAYLOAD_BYTES | 65523 | from 4 through 65523, complete local message string |
| REMOTE_PAYLOAD_BYTES | 64348 | from 4 through 64348, whole remote message bound |
| PILS_STARTUP_TIMEOUT | 10 s | finite and nonzero, on the shared logical clock |

Application backing uses shared contiguous pools rather than large arrays per
channel. A baseline source buffer is reserved per channel; surplus can raise
outstanding credit up to WINDOW. Native RX is allocated at client admission.

| Peer key | Default | Constraint |
| --- | ---: | --- |
| PEER_TUNNELS | 32 | 1 through 64 |
| PEER_CHANNELS | 64 | 1 through 4096 |
| PEER_ROUTES / PEER_ORIGINS | 128 each | 1 through 4096 |
| PEER_FRAMES | 32 | 1 through 4096 |
| PEER_SKIPPED_KEYS | 32 | 1 through 256 per tunnel |
| PEER_WINDOW | 1 | 1 through 4 |
| PEER_USED_CHANNELS | 4096 | at least PEER_CHANNELS, at most 1048576 |
| PEER_MONOTIME_RESERVATION | 1024 | 1 through 1048576 timestamps |
| PEER_MONITOR_QUERIES | 4 | 1 through 16 classified management MQs |
| PEER_MONITOR_RECORDS | 4096 | 1 through 16384 rows/responses, including END |
| PEER_MONITOR_PATH_IDENTITIES | 8192 | 1 through 65536 identities per capture |
| PEER_MONITOR_BYTES | 262144 | 256 through 4194304 frozen bytes per snapshot |
| PEER_OPEN_TIMEOUT / PEER_IDLE_TIMEOUT | 120 s each | finite and positive |
| PEER_SEND_TIMEOUT | 10 s | one original admitted CORE send |
| PEER_SEND_RETIRE_GRACE | 5 s | physical MQ retirement after an unsettled send |
| PEER_SHUTDOWN_GRACE / PEER_FORCED_DRAIN | 5 s each | finite and positive |

Peer payload/frame regions are capped at 128 MiB and combined application/peer
payload pools at 256 MiB. Metadata and native framing are additional; these are
allocation bounds, not measured resident memory. Returned channel packages are
reused only after their effects and IO retire.

## Discovery and monitoring

Non-neighbor opens issue DHT_HELLO GETs with RECORD_ROUTE and
DEMULTIPLEX_EVERYWHERE. `[cadet] DHT_REPLICATION_LEVEL` defaults to 3. Each result
must match the original key/type, verify HELLO and all recorded-path signatures,
and lead through a current CORE neighbor. Native query/open deadlines remain
fixed through STOP, cancellation and source recovery.

Current peer demand also owns bounded TRANSPORT application preferences: one
BEST_EFFORT, bandwidth-zero registration per peer MQ. Retiring a source discards
its registrations; fresh epochs derive requests from current demand.
PEERS/TUNNELS/PATH responses capture bounded Node snapshots.

## Shutdown and statistics

SIGINT, SIGTERM and matching parent-control bytes stop admission. Parent-control
EOF only closes that stream. CHANNEL_DESTROY stops new data/credit/delivery while
accepted outgoing work retains its settlement authority. Remote sends drain on
peer ACK; loopback sends drain after the immutable DATA frame is written.
A fixed 120-second additional channel-drain bound does not extend earlier
operation/process deadlines. Repeated Destroy never renews it.

The shared `cadet` STATISTICS publisher samples after application and peer
retirement while inventory still exists. Queue admission is not a transmitted
message; unknown/partial sends are not counted as written. Nonpersistent
publication retains unconfirmed mutations without replay.
`STATISTICS_TIMEOUT` and `STATISTICS_SHUTDOWN_GRACE` default to five seconds.
