# Source profile

GNUnet tag v0.29.1, commit346358e26d4dcc2dc4f51bef5d52dca29c7d8165. Daemon `src/service/arm/gnunet-service-arm.c` SHA25696c0ba0c52c21fe0d347818fa406a233e341868c8d9561d59d4e96fba62515df.

Source contracts cover the daemon, public ARM API, configuration and testing
interfaces. The [public API inventory](../../spec/gnunet/api/README.md) and
[release criteria](../../spec/gnunet/external/RELEASE.md) retain requirements
beyond this pure service core.

Reviewed source anchors: setup_service1897..2015 registry/default1ms/FOREVER; start_process745..945 and os_process fork/exec semantics; start/stop1160..1322 precedence; LIST1350..1427 ABI and snapshot; notification context strict>1024; shutdown1500..1560 cancel-global-task, close-all-listeners, TERM-all-children; restart1571..1638 global IDLE scan; reaping1648..1864 process clear/STOPPED/stop completion/cooldown from old restart_at/clean exit0 no forced task; client EOF2049..2060 clears requester marker; monitor2070..2086 dedup membership with repeated initial ACK/no snapshot; run2096..2194 initial starts before notifier.

All C-facing wire ABI is explicit ArmAbi: current normal Darwin align8 RESULT24/LIST-prefix24, info28; existing align4 codec requires separate normal-host evidence. No generic C union ABI is imported into owner IDs. Public IDs are local Rust ownership capabilities, never new wire fields. Full configuration/native/CLI/testing requirements remain pending, especially SIMPLE/default-prefix/custom quote parsing and unflushed self-stop RESULT→EOF callback distinctions recorded by the design.

New bounds/ownership profiles: independent caller Scope identity prevents foreign/rebuilt-token revival; no global atomic. Explicit storage failure can close recipient clients but never masquerades as official optional dropping. Real native acknowledgments/child waits and final cleanup cannot fail from ordinary message sequence exhaustion. Valid-operation/source ordering requires host settle before unrelated callback polling; tests are pure source-derived state controls and intentionally do not call an extracted replacement C state machine.
