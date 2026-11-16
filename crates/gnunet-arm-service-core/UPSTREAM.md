# ARM service reference behavior

GNUnet v0.29.1, commit `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.
Daemon source: `src/service/arm/gnunet-service-arm.c`. Exact source bindings
are stored in [source-inventory.json](source-inventory.json).

Source contracts cover the daemon, public ARM API, configuration and testing
interfaces. See the [API inventory](../../spec/gnunet/api/README.md) and
[release criteria](../../spec/gnunet/external/RELEASE.md) for their requirements.

## Source anchors

| Function or path | Contract |
| --- | --- |
| `setup_service:1897..2015` | Registry order, default 1 ms and FOREVER |
| `start_process:745..945`, `os_process` | Fork/exec admission |
| Start/stop `1160..1322` | Request precedence |
| LIST `1350..1427` | ABI and snapshot |
| Notification context | Optional drop only at logical MQ length > 1024 |
| Shutdown `1500..1560` | Cancel global task, close all listeners, then TERM all children |
| Restart `1571..1638` | Global IDLE scan |
| Reaping `1648..1864` | Clear child, STOPPED, stop completion, cooldown from old `restart_at`; clean exit 0 does not force a task |
| Client EOF `2049..2060` | Clear requester marker |
| Monitor `2070..2086` | Deduplicated membership, repeated initial ACK, no snapshot |
| Run `2096..2194` | Initial starts before notifier |

## ABI and scheduling

All C-facing wire ABI uses explicit `ArmAbi`: the selected normal Darwin align-8
profile has RESULT 24, LIST prefix 24 and info 28 bytes. The align-4 codec requires
separate normal-host qualification. Public owner IDs are local Rust capabilities,
with no imported C union layout or additional wire fields.

Independent caller Scope identity prevents foreign or rebuilt-token revival
without a global atomic. Storage failure can require recipient closure but never
masquerades as an official optional drop. Native acknowledgments, child waits and
final cleanup remain possible after ordinary message sequence exhaustion. The
host settles each synchronous body or resumable scan before polling an unrelated
external callback.
