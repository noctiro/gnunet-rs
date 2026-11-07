# Generic service startup

Native process startup boundaries shared by GNUnet service executables. Protocol
and application state remain outside this package. Configuration selection is
shared; identity and process mechanisms follow the native OS.

## Configuration

`configured_user(config, section)` reads `USERNAME` through official dollar and
filename expansion. Missing configuration means retain the selected account;
invalid present configuration returns its original error. It does not perform
account lookup or change process identity.

## Windows identity

`verify_configured_identity(config, section)` queries the process primary-token
user and checks a configured account using native SIDs. It returns the actual SID
or a configuration, Win32 query or identity-mismatch error. Mismatch retains both
observed SIDs. It does not map identities to Unix UID/GID numbers, impersonate a
thread or change the invoking process account. A supervisor must launch under the
required account before constructing the service.

The native SID owner retains only validated identifier bytes. Token handles close
through unique ownership; the SID can outlive the query handle without retaining
privileges. This observation grants no file access, elevation, group membership
or TCP peer authentication. Local peer credentials and process launching remain
separate [platform work](../../IMPLEMENTATION_STATUS.md).

## Unix early resources

Call unsafe `capture_from_environment` as the first fresh-exec operation, before
opening unrelated descriptors or creating a runtime, threads or logging owners.
Its explicit inherited mode adopts listeners or retains their close-after-bind
ownership. Parent control is captured at the same boundary so duplicate raw-FD
aliases are rejected before ownership transfer. Later adoption failure requires
startup exit; do not retry capture or log through a declared foreign stdio slot.

Original inherited descriptors are neither reopened by number nor reconstructed
later. Listener borrowing and newly created pathname cleanup follow the
[shared runtime contract](../service-runtime/README.md).

## Unix account transitions

`resolve_user` constructs a native account plan. `apply_privileges` is an explicit
fresh-process operation after privileged listener preparation and before unrelated
async work. It follows the selected initgroups capability, native gid/uid order
and fallback, retaining the failed stage, errno and observed IDs on refusal.
Partial transition failure requires process exit. A successful fallback does not
prove supplementary groups were reset or saved credentials were discarded.

Library embedding checks that the caller already has the selected identity;
it must not mutate the entire process behind the embedding application's back.
Native command and original child ownership are described by
[the process contract](../service-runtime/PROCESS.md).

## Unix detachment and readiness

Unsafe `daemon::split` requires a fresh single-threaded process after early
capture and flushed option/log selection, before account lookup, runtimes,
threads, children or path guards. One fork and child setsid detach the process;
stdin/stdout redirect to `/dev/null`. Captured listener/control and selected log
owners remain. New private pipe ends are lifted above stdio before replacement.
This is not an async embedding API.

The original parent drops captured copies and waits for its one status-pipe byte,
not for the live daemon to exit. The kernel reparents the daemon when that parent
exits; no later reaping result is invented. The status reports `.` once after host
readiness, `I` for initialization failure and `S` for stop-before-ready. EOF and
read errors fail startup. Drop never reports ready; `finish` retains the original
service error and independent status-write failure. Post-ready failure cannot
retract the earlier readiness observation.

## Verification

[Native runtime tests](../../tests/README.md) exercise shared TCP services and
platform identity observations. Unix process tests use owned children and private
files/sockets. Credential-changing or device profiles require their documented
native setup; ordinary embedding tests perform neither operation.
