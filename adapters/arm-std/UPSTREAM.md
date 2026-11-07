# Official source and scope

Pinned GNU GNUnet v0.29.1, commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`. The machine inventory binds the
public header and complete implementation files. `tools/reference.py` validates
HEAD/tag, clean complete tracked source commitment, old normal-build receipt,
all declared ARM/util library hashes, generated compile configuration and
compile database before and after each fresh comparison. It never rebuilds or
changes a normal C library. Output must be disjoint from all inputs.

| Official public API | Rust entry points / original authority |
|---|---|
| GNUNET_ARM_connect | ClientHost::connect, initial logical MQ + TEST, physical retries held in same epoch |
| GNUNET_ARM_disconnect | ClientHost/CallbackContext::disconnect, original callbacks and close obligations |
| GNUNET_ARM_operation_cancel | ClientHost/CallbackContext::operation_cancel, callback suppression without wire retraction |
| GNUNET_ARM_request_service_list | request_service_list, RX-borrowed Inbound::List |
| GNUNET_ARM_request_service_start | request_service_start, LocalLauncher, native helper and caller ChildRegistry |
| GNUNET_ARM_request_service_stop | request_service_stop, original STOPPING waiter versus pending EOF |
| GNUNET_ARM_monitor_start | MonitorHost::start, independent MONITOR MQ |
| GNUNET_ARM_monitor_stop | MonitorHost/MonitorContext::stop, immediate physical closure |

The four callbacks, three opaque handle representations, enum/status values,
ServiceInfo fields and VERSION=3 are delegated to the existing official core.
Callbacks hold borrowed list/status bytes only during invocation; compile-fail
and positive counterpart docs enforce that boundary. Configuration/path helpers
are the shared ProjectData and CLIENT APIs, including the shared process-global
raw libexec/SUID cache. Explicit isolated snapshots instead borrow their caller's
BinaryPathCache; this is a named separate process-equivalent context.

Source `arm_api.c:824..1013` creates the nonblocking pipe before inspecting
BINARY, runs the source command parser, and waits for readability, EOF or its
original 60s deadline. None proves successful target exec or service readiness.
`os_process.c:570..842` admits fork before execvp, preserves ignored signal
dispositions and mask, maps stdio, deploys optional control pipe and inherited
readiness fd. The Rust helper preserves late exec failure and sampled SIGPIPE;
parent process state is not changed by production launch. POSIX spawn returns
positive errno, which the small native wrapper checks explicitly as nonzero.

The low-stdio C defect is defined unsigned conversion, not undefined behavior:
`gnunet_common.h:123` has the ordinary conditional GNUNET_MAX macro;
`os_process.c:628..671` combines unsigned max_fd and target_fd=-1 for an inherited
lsock, yielding UINT_MAX and then pos=0. The source relocation may be skipped;
`map_std` subsequently overwrites a low pipe source. Normal C observations retain
16 null-readiness and 2 occupied-stderr profiles separately. Safe Rust lift and
restoration preserve the readiness FIFO and caller's inherited closed
stdio rather than reproduce this defect. It adds no network field or success.

The current inventory keeps incomplete branch validation visible: additional
command/PATH/context cases, ready-byte observation, selected malformed/bounds
and monitor cancellation branches are not promoted by API presence or matching
fixture counts. Full ARM daemon managed children/restart/listener inventory,
CLI and six TESTING APIs are separate pending work. C undefined callback-mismatch
or NULL callback paths are not invoked as a differential oracle; existing core
safe original-operation ownership is retained.

Run `python3 -B tools/verify.py --package <package> --repo <repository>
--source <clean-pinned-upstream> --reference <normal-ARM-build-result.json>
--output <fresh-disjoint-directory>`. It uses the package manifest,
pinned locked/offline Cargo and an output-local target with at most two jobs.
The result separates native matches, known official defects, Rust safety checks,
lifecycle waits and unfinished owner scope. No report is auto-promoted to
verified or a complete ARM implementation.
