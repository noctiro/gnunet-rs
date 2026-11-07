# Rust official TRANSPORT foreground

`gnunet-service-transport -c transport.conf` uses the shared SERVICE
option table `-c/-d/-h/-L/-l/-v`. `-v` is version; PROGRAM-only verbose and
GNUNET_ARGS behavior is not added. Its existing PROGRAM embedding scheduler
remains available to callers with a genuine `Prepared`; the binary never fabricates one.

The standard binary first captures original inherited listener and parent-control
descriptors, then selects options and the Logger. `-L` filters driver
and cleanup diagnostics and `-l` selects the owned log file. The explicit callback
owner routes diagnostics without process-global installation or fd2 replacement;
first diagnostic IO failure requests ordinary source shutdown and survives all
original joins as an independent failure.

`-d` uses the shared fresh-process daemon split before configuration, account
lookup, runtime, listener pathname guards or workers exist. The child calls
setsid and redirects stdin/stdout to `/dev/null`; the original stderr, selected
log file, activation and parent-control owners remain intact. Logger PID metadata
is refreshed without reopening the chosen file. The original parent drops its
copies of activation/control and blocks on the original status pipe, not on the
live daemon lifetime. Only the child-ready byte permits parent success;
failure, early stop, EOF and status IO error cannot mean ready. The private log
file owner is already lifted above fd2 by Logger setup.

After detach the service loads official defaults/selected configuration and
resolves `[transport] USERNAME`. Its sole current-thread runtime is entered only
for original listener adoption or synchronous TCP prebinding; identity/initgroups
changes occur outside async work. The selected account then creates new Unix
paths through `ListenerPreparation::finish_with_access` using the same
`UNIX_MATCH_UID`/`UNIX_MATCH_GID` flags as kernel credential admission. Absent
flags impose no identity match; UID matching takes precedence. New socket/parent
modes are 0700/0700 for UID, 0770/0750 for GID, and 0777/0755 for neither. Existing
parents and inherited sockets keep their ownership and permissions. Only after
listeners exist does it create private store parents and open the marked
`Reservations` worker.

`foreground::service` receives that configuration, same SharedClock,
settings, original `Listening` and reservation owner. It invokes the same real
session/DV driver used by `foreground::scheduled`, including original source
epoch rebuilds, finite socket grace, queued/partial retirement and mandatory
worker drain/join. Existing algorithms, nonce/stamp authority, CORE/communicator
framing and SIGINT/SIGTERM/parent-control handling are unchanged.

A once-only ready callback runs only after the Owner permits local IPC
admission (verified original PILS identity and persistence barrier cleared). It
logs through the selected Logger, writes `READY <public-peer-hex>` to the actual
stdout, then consumes the original child status writer. Neither a bound listener
nor a queued publication is readiness. Callback failure follows ordinary stop and
cleanup, preserving the original error. Epoch rotations do not notify the parent
again. This fact asserts local service availability, not remote peer connectivity.

`[transport-rust] MONOTIME_STORE` defaults to
`$GNUNET_DATA_HOME/transport-rust-monotime`. This is an independently marked
`Namespace::Transport` directory carrying the public eight-byte generation
highwater. The backend refuses foreign/unmarked existing directories before
reading business bodies. The binary does not read C identity files or adopt C
monotime/key storage. An existing marked directory whose canonical state is
missing is an error, preserving the admitted reservation fencing policy.

The example retains active official `[transport]` endpoint and ACL keys from
pinned `transport.conf.in`: HOSTNAME localhost, the standard Unix socket path,
loopback ACCEPT_FROM/ACCEPT_FROM6, BINARY and optional USERNAME. It adds explicit
Rust resource limits in the separate `[transport-rust]` section. It does not
start communicators or dependency daemons. Provide supported external
communicators and PILS/PEERSTORE/NAT/STATISTICS endpoints as required by
the composed runtime; a listening local MQ is not an authenticated remote link.

## Bounded resource policy

Settings are read before any worker/listener/native CLIENT is created. Invalid,
zero, unrepresentable and forever native timer values fail during startup. The
assembled complete PILS/HELLO/own-address output bounds are checked with the
existing `PublicationBounds::checked` before any native effect is accepted.

The main defaults are32clients,128queues,64known peers,256message metadata
entries,4MiB shared payload,8control messages and4KiB control bytes. Reassembly
has a64entry shared limit and32per-peer attribution limit. Existing outgoing
retry bitmaps have an additional `messages*8192` ceiling; that memory is not
silently counted as payload. `PENDING_BYTES` is a256KiB per-accepted-source native
FIFO ceiling, with buffers allocated by retained bytes.

Discovery defaults to16explicit per-peer monitor slots and one general query MQ,
256candidate entries and256KiB candidate byte capacities. HELLO parser
scratch is shared; there is no per-peer maximum-payload vector in this provider. Default candidate address cap4096, HELLO cap65535/count256, ingestion quantum16,
IO quantum8. PEERSTORE native source/output/operation budgets are separate and
bounded. PILS has one shared source with24original job metadata rows. The
configuration file lists each source/operation/provider-init/partial/retirement interval;
new payload or a cancelled future never remints an original deadline. Accepted
application MQs have no INIT or first-frame deadline: idle sources remain under
`CLIENT_SOURCE_LIFETIME` and the accepted-source cap. `CLIENT_INPUT_LIFETIME`
begins at the first partial byte and progress cannot renew it. `RECOVERY_WINDOW` governs service-source recovery and stable restart backoff,
independently of client input; PEERSTORE connection initialization uses its own
`PEERSTORE_INITIAL_LIFETIME`. The removed `CLIENT_INITIAL_LIFETIME` option is
rejected when present.

All record and protocol credit/result distinctions come from the provider
owners. Capacity waits retain original immutable bytes and ownership. Shutdown
grace bounds native MQ cleanup; an already admitted OS fsync/rename/worker join
is observed to its result and is not claimed forcibly interruptible by that
socket grace.

## current limits

- `[PILS] PROFILE=reference029` selects the ordinary official build;
  `deterministic` selects its address-hashing conditional build. The same typed
  choice governs PILS, discovery, publication and HELLO storage verification.
  An explicit local `PILS_PROFILE` must agree with the node choice. Ordinary
  HELLO coverage is metadata-only; conditional coverage includes addresses.
  Public addresses remain candidates pending transport validation.
- `USE_BURST_NAT=YES` enables bounded burst attempts using HELLO candidates
  and official `TRANSPORT_START_BURST` (1253) messages for a registered
  `can_burst` communicator. The normal UDP entry enables its native NAT burst
  provider and original `TRANSPORT_BURST_FINISHED` (1254) completion path;
  default NO keeps ordinary fallback behavior. A command write or burst
  completion does not prove a validated route or remote reachability. Actual
  NAT traversal, platform behavior and performance still require qualification;
  the private TCP observations do not qualify burst traversal.
- The Owner/Server chain uses typed independent `Times`: scheduling,
  RTT and retry use native elapsed microseconds from one immutable node anchor;
  records use the canonical GNUnet absolute clock. Absolute correction or
  revision does not masquerade as elapsed mono time. Existing queued STORE
  expiry and original operation/native hard targets are retained exactly.
  CLOCK_PROFILE_TOLERANCE was removed because this is no longer an anchored-UTC
  scheduling profile. Each child provider still applies its own validity,
  authentication and original deadline policy; a correction is not a substitute
  for a new identity/operation receipt. Own certificate/HELLO APIs remain
  on an explicit actual-UTC policy, while strict restart-safe sender-monotime
  floor integration remains a separate reservation task.
- Full TRANSPORT scope, all communicator implementations and complete GNUnet
  acceptance remain independent work. This program delegates to current T2
  composition; it does not upgrade declaration/queued/written events into peer
  readiness or imply a complete node.

No C/private key
files, old transport-node or stopped DHT/UDP/GNS owners were accessed.
