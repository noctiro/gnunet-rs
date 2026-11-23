# Ordinary SECRETSHARING service

`gnunet-service-secretsharing -c service.conf` runs the official IPC endpoint
using original PILS and CONSENSUS sources.

## Startup and configuration

The shared [native SERVICE driver](../../adapters/program-std/README.md#service-startup)
provides standard options, selected diagnostics, configured process identity,
listeners, original parent control and bounded readiness submission. Unix
prepares inherited/TCP listeners before privilege changes, then completes local
endpoints under the configured identity. Windows verifies the process token,
imports activation and selects managed console detachment or standalone re-exec.

Missing Unix credential settings default to UID=YES/GID=YES on Unix and NO/NO
on Windows. Explicit Unix credential checks remain unsupported on Windows;
endpoint ACLs retain native policy. Immediate shutdown is the default.

## Operations and ownership

`READY` reports bound listeners and active IPC admission. PILS identity and
CONSENSUS readiness are checked as each request needs them.

- `DECRYPT` (781) uses the supplied share. Threshold-one decryption verifies
  the local partial signature and interpolates the result locally. Higher
  thresholds use CONSENSUS to collect verified partials.
- `GENERATE` (780) uses a local path for threshold one with an empty roster or
  the verified local PILS peer as its only member. On success it returns a
  430-byte `SECRET_READY` (783) frame. Local preparation can begin before the
  requested start time. The service waits until that time and retires the PILS
  connection before queueing the result. Multi-peer generation uses the native
  CONSENSUS workflow, subject to admission and the
  [FAIR construction limits](../../crates/gnunet-secretsharing/README.md#fair-construction).

Each connection admits one request. The configured quota and the earlier of the
service's operation deadline and the request deadline bound the work. The
service records local completion after writing the full response frame and
retires client and dependency connections independently during cleanup.

## Resource policy

The `[secretsharing-service-rust]` resource profile has MAX_CLIENTS16,
MAX_OPERATIONS8, OPERATION_BYTES32 MiB, TOTAL_RETAINED_BYTES512 MiB, FRAME_BYTES
65535, IO_SLICE_BYTES65535, FIRST_INPUT30s, PARTIAL_INPUT15s,
OPERATION_TIMEOUT300s, OUTPUT_TIMEOUT15s and SHUTDOWN_GRACE10s defaults. NATIVE_RETAINED_BYTES, MAX_PEERS, MATH_PARTICIPANTS, MATH_RETAINED_BYTES and
WORK_UNITS expose the installed decrypt/math owner's existing finite resources. INDEX_ORDER explicitly selects native/little/big for C's serialized original
indices; native is the default. RESOLVER_FRAME_BYTES/RESOLVER_IO_SLICE_BYTES/
RESOLVER_OUTPUT_FRAMES retain the common Resolver's explicit limits. All
impossible/inconsistent profiles are rejected before listeners/business work. Configured maxima are independent; no promise of all maxima at once or RSS is
made. Node-wide `[PILS] PROFILE` is selected once before listeners/business work
and passed through the same native decrypt policy to both781 and780, including
the singleton and general generation owners. It defaults to `reference029`
(alias `reference-0.29.1`); `deterministic`/`reference-deterministic` selects the
official conditional address-derived mode. Explicit `lsd0014-text` remains the
separate published textual interpretation, without official C compatibility
credit. Unknown profile names fail at startup.
