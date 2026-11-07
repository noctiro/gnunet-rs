# Scoped bounded ARM service core

This workspace package implements pure official ARM server state; it is not a
complete native ARM daemon, CLI, configuration loader or testing framework. The fixed official source inventory and earlier candidate proofs are retained;
integrating this core awards no full ARM compatibility status.

The production graph remains no_std/noalloc/forbid unsafe: only existing ARM wire/types dependencies, caller-owned service/client/listener slots and distinct exclusive frame buffers. No libgnunet FFI, sockets, spawn, DNS, global random source, AtomicU64, global ID allocation or invented protocol is present.

## Construction and identity

Create caller `OwnerScope`, immutable host-prepared `ServiceSpec` registry in official enumeration/head-insertion order, metadata arrays and independent `FrameSlot` slices. `Owner::new(&mut scope,specs,services,clients,listeners,frames,abi)` preflights the complete representable LIST before resetting metadata.

All public client/service/child/native/frame/listener/readiness/timer/final-shutdown tokens borrow the original nonzero-sized scope. Scope equality and hashing use reference identity (`ptr::eq`/`ptr::hash`), never identical marker field values; Debug output is no permission proof. Runtime foreign-scope tokens reject before mutation. A retained old token prevents safe reborrowing the same scope for another constructor: E0499 negative and positive reinitialization controls execute in `tools/ui.py`. This applies even when constructor resets the same backing slot generations; no stale token can be used against that reset in safe Rust. Metadata internally stores unbranded private keys so no stale scope borrow is hidden in reusable caller storage.

`identity()` retains this same scope identity even for an empty or fully drained
registry. `owns_service()` checks original registry membership; it does not grant
an old service token renewed spawn, listener or child authority.

Register managed listeners only after the host really owns each successfully bound socket. Configuration phase permits this, not client admission. Drive `startup_next` through every initial spawn attempt until it returns false; the phase becomes Serving and only then `connect` succeeds. No initial STARTING replay/snapshot is invented. A refused forced preparation does not advance its startup/scan cursor or skip into successful Serving.

## effects and host-input boundaries

`NativeEffect::Spawn` is an unexecuted request. Disarm all source service readiness first, perform native fork-admission-equivalent creation, retain native capability under scoped ChildId, then call `spawned`. C's exec-confirming spawn mismatch remains a host prerequisite. `SpawnOutcome::Admitted` does not mean application ready. Native leases are taken once, retained across future cancellation and checked with `native_current` before I/O; stale attempt epochs cannot acknowledge a later TERM on the same child.

Listener Arm/Disarm/Close operations have scoped lifetime/generation/operation tickets and explicit `listener_applied`. Taking an effect does not change state. A pending Arm is retained when desired state changes; its completion is tracked before a subsequent Disarm/Close. Readiness events carry the particular armed-registration epoch, so old registrations cannot launch another generation. ARM never accepts the queued connection. Ordinary operations may be aborted only if the host confirms no I/O occurred; a Close lease cannot simply be abandoned.

Single global IDLE restart scheduling uses leased `TimerEffect` Arm/Cancel, actual `timer_applied`, and scoped `timer_fired`. Abnormal reap requests the source's immediate IDLE task first; only firing enables its scan. A scan computes future UTC wakes. Clock regression rechecks UTC and registers a new task. Cancellation consumes existing task identity without minting a new epoch. A registered or leased task persists until completion/cancellation; stale/foreign IDs cannot affect a replacement.

Valid `reaped` is an owned-child wait result. It always retains/retires child authority regardless of ordinary output/operation counters; failed output becomes explicit recipient resource closure, with queued/reserved buffers revoked. Required reservations include their own generation to prevent reused buffers receiving an old completion. An consumed `demand` event is also irreversible: generation/epoch exhaustion records that registration consumed, pauses siblings, reports Exhausted, and creates no Starting/child/native lease. These actual-input paths do not falsely promise atomic rollback of OS events.

Client requests without host effects preflight native counters/storage before admission. Encoded LIST is a byte snapshot. Required and optional frames are per-client FIFO; a leased earlier frame blocks only that same MQ. Caller must copy into persistent bounded TX before release, preserve partial writes across drive cancellation, and report logical MQ length via `set_mq_length` (kernel ACK is unrelated).

## Cleanup and resource exhaustion

Shutdown requires global timer cancellation before listener closes, **all** parent-listener Close confirmations before **any** child TERM, owned-child waits, then an explicit final generic runtime shutdown lease/ack. `children_drained`, `listeners_closed`, `timer_drained`, `cleanup_ready` deliberately describe different boundaries. Phase Closed occurs only after `runtime_shutdown_applied`; ordinary outputs never imply native cleanup.

During Draining, ARM's own control listener still admits clients: TEST responds
and START returns IN_SHUTDOWN. This follows the native manual-shutdown service
behavior. The managed service listeners described above are distinct owners;
closing them before TERM does not imply early closure of ARM's control listener.

Final listener Close, timer Cancel, final child ShutdownTerm and generic shutdown reuse existing scoped capabilities rather than consuming ordinary operation/output counters. Tests force listener/timer/native/output counters to MAX and still complete the actual-report-driven cleanup chain, including zero client/frame storage. Ordinary new work may return Exhausted; no counter wraps or fake native handle is issued. Unexpected pure Owner Drop invokes no OS effect/callback and makes no completion claim: host retains responsibility for native owners and blocking/final cleanup.

Optional monitor status is dropped by official policy only at logical MQ length>1024. If a source-eligible status cannot fit caller storage, the recipient is explicitly flagged for host closure, not silently counted as an official optional drop. `ReapReport.resource_closures` and `resource_closures()` make this bounded-resource profile visible. Host must actually close/disconnect these clients; resource-closing clients admit no more requests. This is a resource-exhaustion policy, not evidence that C with unbounded successful allocation behaves identically under that artificial limit.

## References

`UPSTREAM.md` binds pinned daemon source and references all121 original design obligations without removing CLI/native/testing requirements. Current core covers source request/monitor/list, startup, actual-effect ownership, stop/reap, source restart arithmetic/scans and manual cleanup ordering. The source's ASCII byte-folding case profile is explicit; arbitrary locale behavior is not certified.

The workspace also composes host registry/listener preparation, the shared native
process owner, daemon reactor, ordinary ARM SERVICE and ARM CLI. Their
source and finite component evidence remain separate from this pure core. Complete
current scheduler/clock, native-platform and unchanged-official-C interoperability
profiles remain unqualified. Testing support is assessed by required active public
behavior, not by reproducing C helper signatures. Pure tests inject applied/native
wait outcomes; they do not execute a native daemon or certify these host paths. Runtime must settle each source synchronous control body/resumable scan before
polling an unrelated external callback, preserving C callback ordering.

`verify.py --repository /absolute/gnunet-rs --upstream /absolute/pinned-gnunet
--output <new external directory>` executes Rust1.99.1 locked/offline, jobs2,
exact named36 tests+2docs, E0499 frame/scope negatives with positive controls,
all copied root lints/Clippy/rustdoc, M0/M4 and a feature-empty production graph. It compares the generated independent manifest with the workspace package
and checks all22 declared official source hashes. Source file sets and hashes are
rediscovered before/after; all outputs remain external. The121 source obligations
remain inventoried, including pending host, CLI and testing behavior.
