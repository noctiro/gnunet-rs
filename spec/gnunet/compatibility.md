# Protocol compatibility

The Rust implementation targets complete interoperability with the selected
official GNUnet protocols. The machine-readable policy is
[compatibility-policy.json](compatibility-policy.json); the selected reference and
open work are recorded in [Implementation status](../../IMPLEMENTATION_STATUS.md).

## Required external behavior

Preserve network and required public service IPC message identifiers, serialized
fields, encodings, cryptography, authentication, state transitions, flow control,
protocol-defined ordering and public artifacts. Cover the complete capabilities
of the subsystem owners and foundations in [conformance.json](conformance.json),
including relevant failures, cancellation, reconnection, restart and recovery.

A codec or one session is narrower than a complete service or node. Reference
revision, standards and supported protocol variants must be explicit. Differences
between specifications and official implementations require an explicit policy;
undefined C behavior must not become unsafe Rust or a fabricated success.

Admission, native writes, remote processing and durable commits are distinct
observations. Interoperability claims require the corresponding unchanged C
participants and actual recorded results.

## Internal design freedom

Rust APIs, object layout, allocation, channels, scheduling, queues, process
topology, plugin registration and private storage formats may differ. Static
typed validators can replace C dynamic plugins; protocol behavior remains the
external requirement. Reproducing C function signatures, internal callbacks,
select loops or helper libraries is not required.

Use appropriate Rust ownership, explicit backpressure, bounded memory and safe
cancellation. Keep protocol-defined timing and observable results while allowing
different internal retry, batching and scheduling policies. The shared
[architecture](../../ARCHITECTURE.md) defines dependency and resource boundaries.

## Validation and claims

Use focused checks while implementing capabilities, then the required
interoperability and native-platform profiles. Compile checks, controlled models,
component comparisons and full service execution retain their separate scopes.
Documentation or policy changes do not refresh earlier results.

Performance comparisons require equivalent protocol and security behavior,
reproducible workloads and measured latency, throughput, CPU, memory and resource
use. Internal C function coverage is reference-navigation data, not a substitute
for external semantic coverage. The [release criteria](external/RELEASE.md)
define the completion gate; unresolved checker and inventory work remains in
[Implementation status](../../IMPLEMENTATION_STATUS.md#pending-qualification).
