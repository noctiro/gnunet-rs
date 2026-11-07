# PROGRAM API

Public Rust interfaces for PROGRAM, GETOPT, logging and daemon lifecycle.

## PROGRAM and configuration ownership

`program::prepare` returns explicit prepared/main authority or an early stop.
A positive legacy parse index after log setup failure is not main authority.
Arguments and config values preserve OS/raw byte strings. The preparation order,
GNUNET_ARGS handling, provided/loaded config cases, ARM.CONFIG, help/version,
main_without_scheduler and conf_and_options return/mutation behavior follow the
pinned source. CONFIG source diagnostics use a synchronous borrowed operation
observer, so nested include/secret warning/error order is routed immediately to
the same Logger/NLS/clock. Local observation overrides a persistent observer for
that whole operation; no duplicate log is emitted and no !Send logger is stored
in Configuration. All *_observed methods and ordinary methods share the same
parser/value bodies.

`Prepared::run_scheduled[_observed]` is a caller-polled scoped Future adapter:
source SPEEDUP start, registered stop, the shared Resolver connect, then
main. Scope owns bounded tasks and original owner/generation TaskIds. Stop/Drop
retires original tickets and drops work outside the mutable admission borrow.
This is not the complete generic GNUNET_SCHEDULER implementation. It must be
replaced/composed with the separately developing generic scheduler for full FD,
pass-marker, shutdown replay and task-context semantics; none are faked here.

The same caller-owned Resolver Context/Driver is required. The port does not
replace an existing MQ, create per-query private resolution, or fabricate a
connection acknowledgement. `broker.rs` implements the canonical M13 IPC
RuntimeClock source and exclusive ClockSubscription. Each independent Driver or
timer reserves a fallible separate subscription. Arc clones share only the time
domain. Registration-time already-due finite delays stay ready across clock
rollback; MAX remains never. Real drive budgets remain physical Tokio time.

## GETOPT

Owned option tables retain raw argument bytes, source GNU ordering/permutation,
required/optional behavior, prefix ambiguity and original canonical callback
names. Helpers own their assigned targets and partial-error updates; cleaners
execute exactly once. Translated help/error rendering happens through the shared
backend. Arbitrary callback implementations remain caller supplied. Known C
undefined malformed relative/base32/NULL-format paths are not executed by any
normal oracle and receive no equivalence credit; Rust typed safe errors remain.

## Logging and native capability

Logger owns the parsed-once policy, static callsite caches, skip/debug/bulk/scope,
custom callbacks, filenames/open files and lazy typed messages. `enabled`, Policy
`enabled`/`setup`, and checked writes are fallible: native regex/snapshot/resource
failure is neither a match decision nor cached. Only REG_NOMATCH is false.
Regex retains its exact compile-locale snapshot through execution/release; the
short native locale guard restores caller selection before custom callbacks.
See NATIVE-CONTRACT.md and pinned primary source blobs.

The fd2 installation API is a distinct unsafe early/exclusive ProcessStderr
capability. Ordinary owned logging is not a claim that process stderr changed.
Installation/rotation/file errors use their source diagnostic level/order, and
old descriptors/templates follow the original failure rules. Scope methods are
scope_enter([u8;16])->saved, scope_restore(saved), scope_get, scope_fresh and the
explicit OS-entropy scope_fresh_os. The adapter does not invent scheduler scope
inheritance; the generic scheduler host must save/restore these around a task.

Native gettext is an explicit trusted library/ABI profile with an unsafe
exclusive startup contract. The loaded handle outlives every native call and
translation Rc. All native bytes are copied before return. Standard gettext's
missing-message/catalog fallback is preserved; backend failure does not
silently become an English success. NlsDisabled is only the explicit NLS0
profile. Native CaseContext clones extend the native read/effect safety contract
beyond ProcessLocale and across config clones/threads. Immutable snapshot and
current-thread selection are deliberately distinct public profiles.

CONFIG float operations in CurrentThread mode use native numeric-C
selection, defined strtof_l range preflight and fixed, correctly typed native
scanf/snprintf calls. Failed lexical scans retain one owned private thread
locale in TLS. Success restores the original selection. Other threads are not
switched by a shared context. TLS cleanup detaches before freeing. Unsupported
native ABI returns an error; platform implementation and execution evidence are
stated separately. No out-of-range source scanf is executed.

## DAEMON / monolith

Registry Context permits legitimate callback-time admission for the next
newest-first run. A launch snapshots registrations before atomically reserving
scheduler slots. Callback context cannot synchronously destroy the active owner.
Nullable cfg uses owned Option decomposition rather than reproducing dangling C
ownership/leaks. Monolith invokes the caller ServiceMain port before daemon
registration. Acceptance invokes an owned service/listener implementation;
a successful stub return alone is never credited as service activity.

## Reporting

`reporting::Reporter` shares the already selected Logger and original SharedClock within a local scheduler. It applies the selected file/level policy, keeps the first output error, and wakes the registered original task. The failure latch remains set after `take_error`; the caller performs its own bounded shutdown and retains that error with `service::retain_diagnostic`. No task, timer, native resource, fallback Logger or new dependency is created. TOPOLOGY and PT reuse this common owner.
