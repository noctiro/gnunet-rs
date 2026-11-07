# ARM daemon reactor component

This Unix std package implements the official v0.29.1 ARM source registry, managed listener ownership, and an IPC/process/timer reactor over the formal `gnunet-arm-service-core`. Managed children use the single `gnunet-service-runtime::process` implementation. No production code calls libgnunet, invents a handshake, or treats a command/effect as a created or ready child.

The caller separately owns the immutable registry and core spec views, scope/slots/byte storage, formal Owner, `ManagedListeners`, dedicated external `ChildRegistry`, `State`, LIST scratch, configuration and environment snapshot. `Driver` only borrows these values. Canceling `drive`, dropping its borrow and constructing a new view retain original native capabilities, pending receipts, partial RX/TX, timers and output tickets. `OwnerId` validates the formal owner even when the registry is empty; immutable registry references cannot be replaced by recycled addresses. Native actions independently validate exact leases and original child capabilities. The native registry is dedicated to this daemon throughout State lifetime; arbitrary multi-consumer registry routing is not implemented. Visible unrelated live originals are rejected before consuming wait, and an unexpected already-completed event returns as an explicit ForeignCompletion receipt, never a successful daemon reap.

`State` owns ARM's control listeners and accepted streams. Managed service listeners belong to a separate readiness registry which never accepts data: the child inherits each original descriptor in source order and consumes pending kernel connections itself. Parent listeners all close before the first shutdown TERM. During manual child drain, ARM's own control listener remains accepting, as the unchanged C daemon does. It closes at final runtime cleanup. A persisted self-stop requester socket stays owned by State after logical MQ retirement and final core cleanup and physically closes at explicit State drop, corresponding to the foreground process exit. Other clients close at runtime cleanup.

Output handoff copies the complete borrowed core frame into a bounded durable per-client queue before releasing its ticket. First positive/EAGAIN/EINTR write attempts change the logical MQ count; zero/fatal writes do not claim in-flight progress. Partial framing and writes survive cancellation. A blocked client does not block another client's control/EOF or original child cleanup. Source IDLE restart tasks are considered only after ordinary active I/O; a nonconsuming kernel check compensates for delayed Tokio readiness hints. Empty TX and unregistered/disarmed listeners do not suppress IDLE. A timer is polled/registered before its lease is acknowledged, retains the original UTC target across backward clocks, and reevaluates UTC on an explicit later drive after a forward change.

Source startup, restart and shutdown callbacks remain synchronous logical settlements across spawn/TERM acknowledgments. No consuming child-death callback runs midway through those source scans. Cooperative budget yields preserve those unfinished effects and do not poll unrelated I/O first. Real admitted children are installed in both the external registry and core mapping before fallible UTC/core acknowledgments. A consuming wait observation remains retained until acknowledgment. Only an shared `process::spawn` Capacity return becomes an explicit host-profile START_FAILED refusal with an AdmissionCapacity diagnostic; no child/fork/exec is claimed. Other setup/configuration/IO errors remain explicit. They are not blanket translated into protocol failure or success, and the external registry retains original cleanup authority.

The source inventory retains all 121 obligations and 22 unchanged official anchors. None is promoted to full daemon acceptance by this package. The implemented component is supported by 36 host tests (17 inherited foundation, 3 framing, 16 reactor), borrowed-RX negative/owned-copy positive documentation checks, and an eight-way C/Rust public-client × unchanged C/new Rust daemon × Unix/numeric-loopback TCP pair. These are finite observations of the specified profiles, not exhaustive behavior proofs.

The `gnunet-arm-reactor-daemon-fixture` entrypoint is an reactor process for those tests. Its positional CONFIG/HELPER/READY arguments and host ready file are integration controls, not a replacement public GNUnet CLI/protocol or an application-ready promise. Selected USERNAME/resource diagnostics are explicitly refused by that fixture. The ordinary [gnunet-service-arm entry](../../apps/gnunet-service-arm/README.md) separately composes standard SERVICE options/logging/configuration, early CLOSE_LSOCKS release, configured privilege changes and RESOURCE_DIAGNOSTICS/wait4 through this package's service module. Those production paths are present; their complete native/platform, installed-helper and unchanged-official-C acceptance remain unqualified.

Run the portable proof with a fixed unchanged normal C ARM receipt:

```
python3 -B adapters/arm-service-std/tools/reactor_verify.py --repository /absolute/gnunet-rs \
  --source /absolute/official-v0.29.1 --reference /absolute/build-result.json \
  --output /private/tmp/fresh-arm-reactor-proof
```

All generated crate/lock/target/binary/log artifacts go under the fresh external output. The runner retains the complete root lint contract, compares declared dependency/features/source roles, validates exact nonempty witnesses and 11 negative controls, re-enumerates all original and generated file names before/after, and rechecks the unchanged tracked C tree and declared normal libraries. It never upgrades the overall ARM/GNUnet goal to complete.

The public C actor waits the finite fixture child’s exec marker before asserting a signal15 result. An earlier normal-C trial observed exit1 when STOP arrived in the inherited pre-exec GNUnet signal-handler window. STARTING remains native admission only. Exact cross-backend pre-exec signal-result parity is an unproven native-profile boundary, not certified by this pair.

The existing `tools/verify.py` retains the three normal-C managed-listener
cases and the shared native/runtime regression scope. The reactor verifier is
separate. Both freshly build the sole `gnunet-arm-spawn-helper` producer; this
package publishes no second process helper. For standalone host tests, build
`cargo build -p gnunet-arm-host --bin gnunet-arm-spawn-helper` into the same target
first. Full-workspace tests already build this binary through ARM host targets.

Ready ordinary sources, client sessions and each stream's RX/TX direction rotate
after progress. This prevents a finite earlier message backlog from
blocking later clients or queued managed demand. The failing pre-change Rust
witness and the normal-C64-TEST/one-LIST observation are retained separately;
this fairness property does not certify every ordering of the full scheduler. The ordinary SERVICE composition has separate source and static-check evidence; these finite fairness witnesses do not qualify all current scheduler, clock or native profiles.
