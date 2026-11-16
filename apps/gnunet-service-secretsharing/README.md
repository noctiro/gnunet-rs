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

The actual `gnunet-secretsharing-host::Server` composes standard781 with the
installed original-share decrypt owner. READY is printed only after actual
listeners are bound and the IPC owner can admit; it explicitly says
`decrypt781=available generate780=singleton-only`. It is not proof of a current
PILS peer, successful threshold computation, available quorum or full SS/DKG. Dependency identity/proof/source readiness is checked by each original
request. Threshold-one781 uses the local purpose23 signature, sealed
PartialVerifier and original Combine/public-key interpolation checks without
constructing Consensus. It retains the full original share and waits for the
original start; no525/insert receipt is invented. Higher-threshold781 retains
the cooperative Consensus workflow. Standard780 is implemented only for threshold1 with an empty peer list
or exactly the current verified PILS local peer. It returns one real430-byte783
with threshold/count1, local/original index0, local peer and sigma/public
key equal to the existing commitment job's g^a0. Existing nonzero1..q-1 sampling
and original-index Horner supply the secret. Foreign, duplicate or larger
rosters and other thresholds are refused; no remote FAIR proof is invented.

Random preparation may precede the original absolute start, while output waits
for that time and stays within the original finite admission/rawdeadline minimum. The same quota, client EOF/duplicate, partial output and independent cleanup
paths cover both request kinds. The PILS source is retired and checked
idle before zeroizing783 secure queue admission; no Consensus MQ is started for
this singleton. This does not establish multi-peer DKG or legacy-peer identity
compatibility.

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
credit. Unknown selections fail and verification never falls back. This choice
does not change `INDEX_ORDER`, original identity/epoch/request bounds, or the
documented general multiparty FAIR limitation.

Each admitted original MQ owns one780 or781, its fixed admission/absolute-deadline
intersection, native source and output receipts. No private-key file,
Share fixture or DKG transcript is loaded by this app. The original private
request is passed only to the decrypt owner. No worker or implicit
service process is spawned. Signal, Logger or Resolver failure fences ordinary
source IO; cleanup independently retires original clients and dependencies and
retains debts before STOPPED. Only complete136-byte782 or430-byte783 whole writes count
as local result writes; they do not acknowledge client processing.

General multi-peer FAIR production/DKG remains unfinished. Normal C client interoperability and failure/platform acceptance remain open.
