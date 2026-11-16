# Service startup contracts

Shared startup separates process preparation from application readiness.
The [public guide](README.md) covers Unix and Windows composition; this page
records the Unix descriptor, parent-channel and privilege contracts derived from
GNUnet v0.29.1 at `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.

## Parent channels

| Channel | Meaning |
| --- | --- |
| CLOSE_LSOCKS, service option bit 4 | Release the inherited descriptors after configured bind; no status byte |
| Daemon status pipe | One byte: `.` after accept-task registration, `I` for initialization failure, `S` when the scheduler/server did not start |
| GNUNET_OS_CONTROL_PIPE | A separate child read endpoint carrying process-signal bytes |

CLOSE_LSOCKS releases ownership before user switching, daemonization and
application initialization. Abort also releases it, so EOF does not establish
successful startup. ARM passes a pipe through this channel; validation requires
unique open descriptors rather than socket type. `CloseAfterBind` and
`AdoptListeners` are mutually exclusive ownership choices from one capture.

The daemon parent treats EOF or an unknown status byte as failure. These status
bytes are separate from service IPC. Control hints use hexadecimal descriptor
prefix parsing, including the reference's accepted trailing text; the control
reader owns bytes, while the service loop owns signal handling.

## Early descriptor ownership

Call unsafe `capture_from_environment(mode)` once before opening configuration,
logs, runtimes or other owners of inherited descriptors. Validate the complete
declaration and every open descriptor before ownership transfer. Reject duplicate
numbers and aliases between activation, readiness and control. Distinct numbers
referring to the same kernel object remain independent valid owners.

Foreign descriptors 0, 1 and 2 move to fresh CLOEXEC descriptors before their
standard-stream slots are restored to the null device. Reserve every move before
restoration. Failure after adoption is terminal; retrying the old numbers could
close unrelated resources. Owned handles perform later cleanup.

`RebindHold::complete_after_bind` requires a borrowed `BoundListeners` and releases
only its retained descriptors. Drop or abort releases them without a successful
startup claim. `ReadyWriter` owns its descriptor and attempts one status write;
local completion does not prove that the parent read or processed it.

## Configured identity

The reference fetches USERNAME through `get_value_filename`, including dollar and
filename expansion. A relative name can therefore become an absolute path and
fail account lookup. Direct `resolve_user` accepts opaque Unix account names and
is a separate primitive. A present invalid configuration is a startup error;
Rust does not silently continue as a different user or substitute a basename.

Account lookup preserves native name bytes and reports unavailable accounts.
The native primary sequence is short-circuit `setgid`, `setegid`, conditional
`initgroups`, `setuid`, `seteuid`. Failure selects short-circuit
`setregid(gid, gid)` and `setreuid(uid, uid)`. Successful fallback does not prove
supplementary-group initialization; the result reports both facts.

A failed transition can leave partially changed credentials. The process must
exit instead of continuing or attempting rollback. These operations run after
privileged listener creation and before asynchronous work or threads.

## Errors and reference boundaries

Malformed positive FD declarations, aliases and overflow are rejected before
adoption. The reference's partial acceptance and invalid-context paths do not
require unsafe Rust behavior or deliberate execution of undefined C behavior.
Raw descriptor access and early environment consumption remain explicit unsafe
boundaries; native identity calls are isolated in their platform adapter.

The [inventory](inventory.json) records source anchors. Test fixtures distinguish
injected call ordering from observed native effects; neither a component result
nor a descriptor release establishes application readiness.
