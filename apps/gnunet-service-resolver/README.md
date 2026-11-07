# Official Resolver SERVICE

`gnunet-service-resolver -c /path/to/official.conf` runs the bounded
Resolver core, native IDNA backend and UDP DNS stub over official request4/
response5. Standard shared SERVICE options include `-h/--help`, `-v/--version`,
`-c/--config`, `-L/--loglevel`, `-l/--logfile` and `-d/--daemonize`.

The fresh process first adopts original activation/parent-control descriptors. Explicit daemon separation runs before runtime, account lookup, listener path
guards or machine-file reads. The parent drops only its inherited copies and
waits for the child status; EOF/failure is not readiness. The selected
logfile is retained and child PID metadata is refreshed after fork.

The standard main loads `[resolver]` settings, prepares original activation/new
TCP listeners, applies configured `USERNAME` through shared native privileges,
and creates new Unix listeners under that identity. It then reads literal
`/etc/hosts` and `/etc/resolv.conf` once (16 MiB maximum each), constructs the
Host and installs the same SharedClock used by logging/testing skew before
loading machine data or enabling lookups. No key file, C resolver process or
system NSS/DNS request fallback is introduced. Account/group lookup used by
startup or Unix credential policy is a separate explicit native boundary.

`UNIX_MATCH_UID`/`UNIX_MATCH_GID` default to false when absent; the official
resolver.conf sets both to NO. Actual accepted Unix connections use kernel peer
credentials and shared UID-first/GID-or-group policy. The same flags select the
permissions of new Unix sockets and newly created parents: UID 0700/0700,
otherwise GID 0770/0750, otherwise 0777/0755. Existing parents and inherited paths
are not chmodded. TCP IP ACLs remain in force. The library embedding path never changes whole-process identity: a configured
account must already match the current real/effective IDs.

`READY resolver` and the once-only daemon ready byte follow Host/core/
stub/IDNA/policy/machine-data/listener construction. They do not assert an
upstream DNS reply or a complete GNUnet node. SIGINT/SIGTERM, matching parent
control, selected-log failure and original drive/clock errors all stop admission
and close original client streams/UDP owners/listeners. Default shutdown is
Immediate, matching official `GNUNET_SERVICE_OPTION_NONE`. The original runtime
error and independent cleanup/logging error remain observable; only newly owned
Unix paths are removed. `STOPPED` is written after cleanup.
