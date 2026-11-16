# Implementation status

This page tracks known implementation limits and pending qualification.
Source implementation, native execution and full GNUnet interoperability are
separate claims.

## Reference target

- Baseline: GNUnet v0.29.1, `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.
- Selected upstream master, revision checked 2026-11-16:
  [`14698f19848af867f48a04521e274abd55972075`](https://git.gnunet.org/gnunet/gnunet/commit/14698f19848af867f48a04521e274abd55972075.html).

Results must identify the revision they actually used. Updating the selected
reference does not refresh older runs.

## Known limits

| Area | Remaining constraint |
| --- | --- |
| Windows local IPC | Native AF_UNIX datagrams are unavailable. Requested Unix UID/GID peer checks are refused; native listener ACLs are a separate admission policy. See [credentials](adapters/service-runtime/src/credentials.rs) and [listener security](adapters/service-runtime/README.md#configured-local-listeners). |
| DNS interception | Windows driver classification/interface binding is not atomic; check-to-injection races and subinterface replacement remain unresolved. PF excludes IPv6 link-local-source traffic, and native zone preservation for link-local endpoints remains unresolved. Periodic PF policy/interface observations cannot exclude changes between checks or provide atomic interception. See [Windows capture constraints](adapters/native-std/WINDIVERT.md#packet-metadata-and-injection) and [PF constraints](adapters/dns-service-std/PF.md). |
| SECRETSHARING | The fixed FAIR response width cannot represent the general canonical 1023-bit share construction. The [prover](crates/gnunet-secretsharing/src/fair_prover.rs) refuses an unrepresentable response; it does not truncate or reduce it to invent a compatible proof. General multiparty 780→783 remains unavailable under this constraint. |
| Messenger AUTHORIZATION | The selected 192-byte record omits the MAC required by its receiver. Key recovery returns `AuthorizationMacOmitted`; no zero MAC or private wire extension is substituted. See the [record contract](crates/gnunet-messenger/README.md#authorization-constraint). |
| Selected C CADET | The encrypted receive path selects the destination header tag, reverses the next-header success branch and includes the detached payload tag in the ciphertext length. The private two-C CADET control also fails. |
| Selected C FS | Downloader AEAD lengths/tag offsets and search plaintext metadata lengths are inconsistent. These paths also fail on C-produced content. |
| Selected C CONSENSUS | The service returns locally inserted values contrary to its public callback contract; early client disconnect during final iteration can also abort it. |

## Pending qualification

| Boundary | Required work |
| --- | --- |
| Official interoperability | Current-source C↔Rust and mixed-node service, encrypted-data and overlay profiles, including generic SET, CONSENSUS grading/final agreement, scalarproduct, Conversation pickup/control/reversed roles, and the selected C defects above. |
| Recovery | HTTP/3 retained-stream recovery after a remote communicator crash; Conversation remote-peer and authenticated Messenger replacement; FS mandatory-keyword discovery after C service replacement and remaining remote-effect retirement profiles. |
| Native platforms | Full workspace and normal service/CLI/recovery execution on Linux, macOS, Windows and FreeBSD. Windows IPC/process/activation, storage/restart, locale and native library paths require execution on Windows; compilation alone is insufficient. |
| Native SDKs and devices | Windows/FreeBSD TLS, QUIC/HTTP3, HOSTLIST, GNS proxy/CA and optional REST OpenID SDK builds/runtime; audio helpers/devices, DNS interception, NAT helpers, VPN/EXIT and FreeBSD TUN/routing/reacquisition/cleanup profiles. |
| PT | Official-peer PRE exit DNS, POST IPv4/IPv6 rewriting, and DNS, DHT, CADET and VPN replacement/recovery. |
| Ownership and resources | Product-wide operation/source retirement, effect-debt accounting, failure isolation and queue, work, memory, output and durable-history bounds. |
| Performance | Comparable latency, throughput, CPU, resident-memory and allocation measurements with equivalent protocol/security behavior. |
| Capability inventory | Complete external semantic inventory and Rust API coverage; separate legacy C API coverage from external conformance in the strict checker. The [entry map](spec/gnunet/external/operation-entrypoints.json) remains a finite navigation subset. |

Release acceptance follows the [compatibility policy](spec/gnunet/compatibility.md)
and [external release criteria](spec/gnunet/external/RELEASE.md).
