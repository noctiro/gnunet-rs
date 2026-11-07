# GNUnet ARM CLI

Only /tmp is writable for this M9 candidate. No root/M8 inputs are changed. Fixed upstream v0.29.1 commit346358e26d4dcc2dc4f51bef5d52dca29c7d8165 is authoritative. inventory.json records all16 CLI function definitions,13 program-specific flags and the PROGRAM/getopt source dependencies. This is a synchronous CLI over the pure-Rust ARM core/Unix-TCP host, not a private protocol or C FFI wrapper.

## Files and interfaces

- options.rs: byte-preserving OsStr argv,13 specific flags, five PROGRAM flags (-c/h/L/l/v), clustered short flags, GNU long abbreviation/equals/missing-arg behavior, option exclusivity, appended GNUNET_ARGS and POSIXLY_CORRECT parsing. Runtime loading uses Configuration::load/default_filename and preserves arm.CONFIG fallback. Locale translation and generic log formatting beyond the tested C locale remain explicit pending items.
- state.rs: exact phase reducer and English output formatting. Options and public output names retain raw native bytes. Action order is kill -> end/restart -> start -> init -> list -> monitor. Request callbacks preserve source success sets and unchanged exit-code quirks. Timeout alone sets2, list errors3, absent ARM business prechecks4. First connection initialization failure logs/shuts down without inventing ret1.
- runtime.rs: caller-owned ClientHost plus optional independent MonitorHost, official presence::test prechecks, persistent drive state, explicit UTC for restart display and monotonic timeout, SIGINT/SIGTERM/SIGQUIT/SIGHUP shutdown and caught nonterminating SIGPIPE. LocalLauncher borrows a caller-owned ChildRegistry; helper path and native ArmAbi are explicit embedding ports. No callback buffer escapes, no detached IO task, and no default new GNUnet option/config key is added.
- src/bin/gnunet-arm.rs: command entry. Its internal helper deployment is colocated with the CLI or resolved via the formal libexec path; this internal port is not an official GNUnet argv/config extension. Installation discovery/layout coverage remains separately documented.
- The helper binary uses the already reviewed gnunet-arm-host helper entrypoint. Helper creation is never target-exec/service-ready evidence.

## Required quirks

start accepts only STARTING/IS_STARTED_ALREADY; stop ARM accepts STOPPING/STOPPED/IS_STOPPED_ALREADY; named kill accepts only STOPPED/IS_STOPPED_ALREADY. Failure callback text is stdout and normally leaves ret0. LIST disconnected prints its stdout failure plus NULL-list stderr and returns3. LIST pre-count prints stopping/unknown rows before any heading, then prints them again in its ordinary row loop; quiet suppresses heading/summary only. The stopped flag -a changes only stopped visibility. Failed restart delay uses saturating UTC remaining and the original rounded unit thresholds.

Monitor is started in run before actions. Status0 is silent; other statuses print stderr unless currently quiet. Entering final monitor phase optionally prints the prompt, then forces quiet=false. Shutdown cancels the original op before disconnecting both owners. Source end is cleared on successful stop, so --end --delete then normally does not delete. If ARM was already absent, end remains set and deletion can run; restart-absent clears restart and sets start instead. All deletion experiments must use only owned/tmp config and home. The production deletion operation follows the explicit user flag and source config paths; no test may point it at user directories.

## Evidence and pending boundaries

normal unchanged gnunet-arm and gnunet-service-arm are selected from the separate source-bound ARM normal build receipt. Tests use isolated empty GNUNET_BASE_CONFIG, owned HOME/config/Unix sockets and finite literal official frames. Argv/help/version/error and phase/result/list/monitor/timeout/delete traces must be observed from C/Rust processes, not mocked statuses or test names. No public DNS/network or account/system changes occur.

Do not mark CLI/PROGRAM/util or ARM owner complete merely because these finite checks pass. Full generic PROGRAM startup (resolver connection/speedup/logging/locale), untested installation defaults/platform ABI and unrelated flags/helpers remain pending until separately implemented and proven. The native current test profile is explicit U64Align8; no pointer-width guess certifies every32-bit ABI.

## Current finite proof and honest differences

The normal C/Rust CLI entrypoints have C-locale argv comparisons and literal
peer comparisons of application output, original request IDs, complete action
frames and callback order. The literal peer is a distinct evidence group, never
counted as the normal service. Separate unchanged normal C daemons exercise both
Unix and IPv4 loopback remote actions with managed child exec and natural
daemon exit0. Another group uses the official PREFIX deployment port to record
its own PID and exec the unchanged daemon, then runs local start/LIST/restart/
LIST/end. Those reparented daemons have public-IPC/listener cleanup evidence; the
harness does not claim a wait status it cannot own. The prefix sets a private
failure-only eight-second alarm; passed cases stop through the public -e request.

Native -s/-O/-E cases use a finite benign child solely to observe exec,
readiness FIFO, stdio and signal state; this child is not a service substitute. SIGINT/TERM/QUIT/HUP are sent only to each owned CLI after its monitor request
and prompt; SIGPIPE must leave the CLI alive until its official -T timeout. No
agent or external process receives a signal.

The -l proof checks routing, append, message body and ERROR suppression. Official logging timestamp/component/PID/severity prefixes are explicitly stripped
for this narrow comparison and remain unimplemented here. The first attempted
non-UTF8 filename could not be created on this APFS profile (EILSEQ); it is retained
as a failed fixture attempt, not claimed as path support. Production functional
paths remain OsString/OsStr/native bytes. Error Display text and full generic
PROGRAM diagnostics are still pending; successful service names retain raw bytes.

One C term_callback branch formats an already formatted name as a second printf
format. Rust always emits that name as data. A Rust-only percent-name regression
exists; no undefined C format conversion is executed. This is an explicit safe
API/output difference, not an erased kill obligation.

## Deployment and embedding boundaries

The standalone staging package contains a forwarding helper binary only so its
fresh target directory has the reviewed helper next to the CLI. Integration must
reuse the existing gnunet-arm-host helper target and **not** install a duplicate
helper definition. The CLI's colocated-helper preference is an internal Rust
deployment decomposition; its fallback uses ProjectData::libexec_binary_path. No extra public GNUnet argv or configuration key selects the helper. Native helper
installation/layout variants remain pending rather than silently certified by the
colocated test build. ArmAbi::U64Align8 is the actually tested normal C profile;
other ABI layouts require an explicit validated embedding Ports value.

runtime::run borrows the caller-owned ChildRegistry. A dedicated process entry
may return without waiting for a deliberately running ARM daemon, as the C CLI
destroys its process handle without killing that daemon. An embedding caller keeps
the registry and its original-PID wait authority beyond the owner. Tokio's signal
registrations are process-global and persist after this embedding call; the
complete generic scheduler restore/locale/resolver/speedup contract is not supplied
by this narrow CLI implementation. Callers requiring arbitrary concurrent signal
ownership need the missing common PROGRAM layer; the standalone CLI owns its own
process handlers.

## Portable verifier

Run `python3 -B tools/verify.py --repo REPO --source PINNED_GNUNET --reference
NORMAL_ARM_BUILD_JSON --output FRESH_DISJOINT_DIRECTORY`. All Cargo invocations
are offline/locked, target output is explicit, and the full root lint
contract is checked. The verifier commits before/after reachable local source
file sets (including non-Rust src data), both Cargo contracts/locks, tools and
fixtures; re-runs Cargo metadata; validates historical normal source state,
private config, compile database, normal ARM/util libraries and CLI/service bytes;
and commits executed Rust and native fixture binaries. A changing root
input makes a run fail. It does not claim the whole repository was frozen and does
not promote any owner or generic PROGRAM requirement.
