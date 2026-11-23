# GNUnet Resolver service

`gnunet-service-resolver` serves official Resolver request4/response5 over native
local and TCP sockets. It uses shared SERVICE options:
`-h/--help`, `-v/--version`, `-c/--config`, `-L/--log`, `-l/--logfile` and
`-d/--daemonize`. Protocol state and machine-input acquisition belong to
[the Resolver adapter](../../adapters/resolver-std/README.md).

## Configuration and invocation

```sh
gnunet-service-resolver -c /path/to/official.conf
```

Windows uses the same command with native paths, for example
`gnunet-service-resolver.exe -c C:\GNUnet\gnunet.conf`. The standard entry loads
`[resolver]` settings and constructs actual configured local/TCP listeners. It
installs the same `SharedClock` used by logging and testing skew before enabling
lookups.

## DNS backend

macOS and Windows delegate A, AAAA and PTR queries to their live system DNS
service. The OS controls routing and name resolution; the app skips static hosts,
upstream and search-domain snapshots. Other Unix targets read `/etc/hosts` and
`/etc/resolv.conf` once, with a 16 MiB limit per file, and send DNS through the
Rust UDP stub. File errors are reported and leave the failed input empty.

## Unix process startup

The fresh process first captures original activation/parent-control descriptors.
Explicit daemon separation precedes runtime, account lookup, listener path guards
and machine-file reads. The parent drops its inherited copies and waits for the
child status; EOF/failure is not readiness. The selected logfile remains owned
and child PID metadata refreshes after fork.

Startup preserves activation sockets, prepares new TCP listeners, applies
configured `USERNAME` through native account transitions, then creates new local
listeners and initializes the DNS backend under that identity.

## Windows process startup

Startup captures the private parent-pipe location once and validates configured
`USERNAME` against the actual primary-token SID before binding. It does not
impersonate a thread or switch the process account.

The normal entry supports foreground operation, configured AF_UNIX/TCP listeners,
private parent control and native console events. Standalone `-d/--daemonize`
re-executes the same image with its original argv/environment/cwd as a detached
child. A private launcher role prevents recursive re-exec. The parent waits for
actual original-child readiness. Failed startup attempts explicit retirement/drain
of its original child and retains independent cleanup failure. stdin/stdout are NUL;
file/pipe stderr is retained by original handle and character stderr becomes NUL.

An already supervised `-d` service detaches its console and standard routes in
place before runtime/handler installation. Its original process identity and
parent control remain unchanged. Native activation imports the original listener
set before registration and retains accept queues without rebinding. Standalone
re-exec forwards inherited listeners to its own original child; creator path
leases remain with their creator. See the [native transfer contract](../../adapters/native-std/SOCKET-ACTIVATION.md).
Native qualification and remaining integration are tracked in [implementation status](../../IMPLEMENTATION_STATUS.md).

## Endpoint access

`UNIX_MATCH_UID`/`UNIX_MATCH_GID` default to false when absent; official
resolver.conf sets both to NO. On Unix, accepted local connections use kernel
peer credentials and UID-first/GID-or-group policy. New socket/parent permissions
are respectively 0700/0700 for UID, 0770/0750 for GID and 0777/0755 otherwise.
Existing parents and inherited paths are not chmodded.

Windows creates endpoint ACLs for the selected owner/group/everyone policy and
retires original opened nodes. Filesystem permissions do not supply POSIX peer
credentials: requested UID/GID authentication remains fail-closed. TCP IP ACLs
remain active on every platform. Library embedding requires the configured
identity to match the current process; it never changes whole-process identity.

## Readiness, shutdown and errors

`READY resolver` and startup status publication follow initialization of the
Resolver, selected DNS backend and listeners. The shared startup path awaits
native asynchronous publication when needed. A Windows write submission confirms
Tokio/Mio acceptance; the parent confirms startup only after reading the actual
`.` from its qualified original-child connection. See
[bootstrap ownership](../../adapters/service-startup/README.md#windows-parent-bootstrap).

SIGINT/SIGTERM on Unix, native Windows console events, matching parent control,
selected-log failure and original drive/clock errors stop admission, retire DNS
work and close client streams and listeners. Parent-control EOF does not
request shutdown. Default shutdown is Immediate, matching official
`GNUNET_SERVICE_OPTION_NONE`. Original runtime errors and independent cleanup,
logging or startup-status errors remain observable. Only newly owned local nodes
are removed; failed explicit cleanup retains its owner for retry. `STOPPED`
follows cleanup. Console shutdown can still impose native OS termination limits.
