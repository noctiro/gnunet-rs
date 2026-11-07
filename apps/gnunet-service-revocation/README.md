# gnunet-service-revocation

The standard SERVICE entry supports `-c/--config`, `-d/--daemonize`, `-h/--help`, `-L/--log`, `-l/--logfile`, and `-v/--version`. It uses the shared SERVICE option/logging owner and first-operation inherited-descriptor capture. Actual process detach occurs before runtime, identity resolution, store and worker creation. Selected runtime diagnostics use the same shared Reporter; a logging failure requests bounded soft shutdown while retaining its original error.

Adopted/TCP listeners are prepared before the configured user/group transition; newly created Unix listeners finish afterwards. Every listener is complete before the new marked inventory or its workers open. The single RuntimeClock and Resolver context are shared by CORE, SETU and STATISTICS. Local `READY` is flushed only after the Server/inventory/workers exist, then the original daemon parent is notified once. It does not claim CORE/SETU attachment, peer reachability or remote revocation acceptance.

Official WORKBITS (default22), EPOCH_DURATION (365days), DATABASE, endpoint, USERNAME, ACL, UNIX_MATCH_UID/GID and shutdown settings are consumed. The C DATABASE itself is never opened. Default Rust store path is the expanded DATABASE with `.rust-store` appended; `revocation-rust.STORE_DIRECTORY` may select another new dedicated marked Rust directory. Existing unmarked/foreign directories are refused before snapshot-body reads. No private-key file is required or read by REVOCATION.

Internal finite bounds and explicit local native source profiles appear in `example.conf`; `CORE_CLASS_ORDER=native` and `SETU_ABI=native` are the current host's exact profiles. Use an explicit profile for a differently built configured producer. These choices change interpretation of existing native ABI defects, not wire protocol message numbers or frames.

The official default is immediate shutdown (`GNUNET_SERVICE_OPTION_NONE`). SIGTERM/parent stop in explicitly configured soft mode stops acceptance and drains original operations under their fixed native bounds and the configured process shutdown grace. A second signal or elapsed grace closes sources immediately. Actual original worker completion/join is still required; a filesystem syscall/hash cannot be preempted or falsely reported as retired. Original task, service, Resolver, verification, snapshot, statistics and output-report failures are independently retained. A diagnostic failure uses a fixed soft grace even when ordinary signal shutdown is immediate.

The existing `gnunet-cli` module provides query, revoke, verify, mine, and prepare commands. Prepare obtains only the explicitly named ego through the configured IDENTITY endpoint and signs the official purpose3 region using the existing zeroizing secret owner; it never opens a private-key file. Mine/check use one explicit bounded CPU worker with per-hash guards and original cancellation. Outputs are new exact372-byte public certificate files; no existing file is replaced. They do not imply service acceptance. Public-key text is the complete typed58-character Base32GNS representation.

Mine resumes the public candidate pool instead of discarding its nonces. Each
unique old candidate is actually rehashed once, within the same original hash/time
budget and reusable1MiB scratch; no saved score is trusted. The public format has
no discarded-nonce cursor: new search starts above max(--start, carried nonces),
and the `search_after` diagnostic can be supplied as the next explicit --start. It is a search floor, not a recovered or authenticated historical count.

SIGINT and SIGTERM streams are registered before the CPU worker starts. A budget, deadline or either observed signal (including a stream error) requests stop but does not invent a work
receipt. The command waits for the same original worker's result and
thread join, then writes its last public checkpoint to the new output. The
command returns failure for unfinished/stopped work even when that checkpoint
was saved. Original worker, cancellation/signal, receive, join, file and output
errors remain separate. `work_target_reached` reports the score target;
`complete` reports mining work completed with a clean join and no observed stop,
independently of the subsequent save/stdout result. `checkpoint_saved` reports
file write/sync success. No local file or mining result grants service
acceptance or current-lifetime validation. Restoration-in-progress is explicit.

Checkpoints are terminal observations, not an active crash journal. A process
crash or an externally dropped computation may lose work since its original
input checkpoint; the input is never replaced. An interrupted/failed new file
must pass the normal exact372-byte read and checks on the next use; no
partial private image, stored score or guessed cursor is adopted.

The five official nonpersistent STATISTICS keys are emitted under `revocation` from CORE connection and SETU result callbacks. Separate monotonic connection/disconnection contributions produce the signed peers-connected gauge. One original native UPDATE is pending at a time; its counter position advances only after the same source wholly writes it. Source loss/error permanently fences that publisher, preserves uncertain deltas, and does not replay them on another MQ. Statistics failure does not stop healthy revocation business; final bounded drain completes before Resolver retirement. These local write facts are not remote processing, replication, persistence or fsync receipts.
