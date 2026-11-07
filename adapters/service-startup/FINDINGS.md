# Addendum to frozen design v1

The design/API freeze precedes implementation. No owner or full generic service
completion is asserted. `inventory.json` remains the original reviewed inventory,
with null verification fields; these local receipts are separate evidence.

## Normal configuration is distinct from direct account selection

`service.c:get_user_name` calls `GNUNET_CONFIGURATION_get_value_filename`.
`configuration.c:GNUNET_CONFIGURATION_get_value_filename` expands dollars and
then calls `GNUNET_STRINGS_filename_expand`; `strings.c` makes relative strings
absolute against cwd. Consequently `USERNAME=noctiro` reaches `getpwnam` as
`<cwd>/noctiro` in this normal profile and fails. Both the unchanged normal C
service and candidate `configured_user -> resolve_user` refuse it, preserve the
original identity, and have already closed CLOSE-mode resources before refusal.
Do not use a raw value/basename silently to manufacture C configuration success.
A present expansion error is an explicit candidate error; C's getter can return
no value and skip switching. This intentional fail-closed difference remains
visible and does not declare all malformed configuration states equivalent.

A separate direct `resolve_user` primitive accepts opaque Unix names, with no
filename expansion. The native exec-child test resolves the current account and
applies only its original UID/GID. On this machine initgroups returns EPERM;
setregid/setreuid to the current IDs succeed, so both implementations return
success through fallback while reporting no successful groups initialization.
The C sequence test extracts the full, unchanged `set_user_id` body and changes
only its declared fixture name-source port. Its syscall wrappers observe actual
native calls and refuse any target IDs other than the child initially held.
This is component evidence, explicitly not normal USERNAME configuration success.

## Readiness has limited meaning

C's CLOSE_LSOCKS success release happens after configured listener bind but before
user switching, daemonization and app initialization. C init-time observations
confirm its original readiness fd was already closed. Abort also produces EOF;
`ReleaseReport` records local phase and consumption of Rust ownership only.
Parent receipt/processing, durable startup, and success after USERNAME are not
inferred. `ReadyWriter` models only the separate daemon status pipe's one-byte
write/close. Complete fork/setsid/parent wait and scheduler status integration
remain pending; the C-only daemon observation is labeled reference-only.

## Defined source versus ownership hardening

Malformed positive FD declarations, duplicates, cross-channel same-number
aliases and original CLOEXEC are rejected before owning any fd. C may accept a
prefix or dereference a failed boxed entry on malformed input; no such unsafe
execution is required as a differential oracle. Separately numbered duplicates
of the same kernel pipe are valid independent owners. Low 0/1/2 resources first
move to new CLOEXEC descriptors, then their stdio slots become the null device;
this is an explicit Rust/libstd ownership adaptation. No ownership Drop later
closes a descriptor merely by its old raw number. Overflow is checked rather than
relying on scanf's out-of-range conversion. These are safety boundaries, not new
successful native protocol inputs or a replacement listener protocol.

The control hint's hex-prefix parser matches the original trailing-text behavior.
The primitive uses signed-char signal values for the tested Darwin C profile;
other C char-signedness profiles need explicit review. Actual signal raising,
AsyncFd/scheduler registration and EOF/error-owner retirement are still caller
integration work. `try_read_signal` does not perform a global signal action.

## Checks

Four named Rust checks include 27 injected primary/fallback-order cases and both
compile-time group branches. Those are deterministic component checks, not 27
successful OS identity changes. Native exec observations additionally cover three
ready bytes/EPIPE, four low/high close resources, duplicate/closed/missing sets,
CLOEXEC, two raw fds sharing a pipe, control alias/prefix, once-only capture,
old-number reuse, bind/failure, missing and current account configuration,
and a current-ID primary/fallback sequence. The test parent identity and
normal C library/source hashes must remain unchanged. No test selects another
account, modifies accounts or `/etc`, performs public DNS, or starts a system
service. Successful tests do not establish full CLI/logger/daemonizer completion.
