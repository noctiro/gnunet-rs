# Implementation status

The complete GNUnet feature set and interoperability target is unfinished.
This page tracks unresolved behavior and required qualification.

## Reference target

- Baseline: GNUnet v0.29.1, `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.
- Selected upstream HEAD, reference checked 2026-11-07:
  `14698f19848af867f48a04521e274abd55972075`.

Results must identify the revision they actually used. Updating the selected
reference does not refresh older runs.

## Unresolved behavior

| Area | Open work |
| --- | --- |
| Platform parity | Complete native services on Linux, macOS, Windows and FreeBSD. Windows still needs standard service executable composition, local IPC, process supervision, peer credentials, native DNS configuration discovery, storage and device backends beyond shared TCP, CLIENT and Resolver service-host support. FreeBSD TUN still needs interface provisioning, IPv6 readiness, route transactions and application integration. Enable equivalent complete-workspace and service/recovery acceptance in CI. |
| SECRETSHARING | General FAIR production across the canonical 1023-bit share domain and full multiparty 780→783. The canonical integer response can exceed the 128-byte field. |
| SET/CONSENSUS | Remaining result modes, typed/empty cases, grading/final results, participant failure and recovery. |
| Identity/recovery | Physical-source replacement, restart and remaining remote-peer recovery across communicators, CADET, Conversation and Messenger. |
| FS | Remaining discovery, cancellation, recovery and remote-effect profiles. |
| Conversation | Pickup/suspend/resume, audio, reversed service roles and remaining hangup profiles. |
| Resource ownership | Complete operation/source retirement, effect-debt accounting, failure isolation and product-wide queue, work, memory and durable-history bounds. |

## Interoperability and platform qualification

| Boundary | Required qualification |
| --- | --- |
| Official peers | Current-source C↔Rust and mixed-node behavior, including remaining CONSENSUS algorithms and authenticated communicator/CADET/Conversation profiles |
| Native platforms | Communicators, NAT/helpers, DNS interception, VPN/EXIT forwarding, devices/privileges and bounded teardown on supported systems |
| Performance | Comparable latency, throughput, CPU, resident-memory and allocation measurements with equivalent protocol/security behavior |
| Capability coverage | Complete external inventory and Rust API access for every required feature; the [entry map](spec/gnunet/external/operation-entrypoints.json) covers a finite subset |

Implementation and runtime qualification are separate. Compilation, a selected
component result or Rust-only peers cannot close the broader requirements above.
Completion follows the [compatibility policy](spec/gnunet/compatibility.md) and
[external release criteria](spec/gnunet/external/RELEASE.md).
