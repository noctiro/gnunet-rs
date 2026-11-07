# gnunet-abd

Ordinary `PROGRAM` command for the installed ABD API, with the standard `-c`,
`-L`, `-l`, help/version and `GNUNET_ARGS` handling. Select exactly one action:

| Action | Required arguments | Actual operation |
| --- | --- | --- |
| `-U`, `--createIssuerSide` | `-e EGO -a LABEL -s 'ATTR text' -T TIME` | Lookup the ego and complete NAMESTORE record set, then prepend one ATTR. |
| `-C`, `--createSubjectSide` | `-e EGO -x 'DEL text'` | Verify the exact signed DEL and current expiry, require its subject to equal the ego, and prepend it at `@`. |
| `-S`, `--signSubjectSide` | `-e EGO -a ROLE -s 'PUBLIC_KEY [ROLE]' -T ABSOLUTE` | Issue a purpose28 credential with the ego's PKEY/EDKEY and print standard DEL text. |
| `-g`, `--collect` | `-e EGO -i ISSUER -a ROLE` | Submit one original native COLLECT request using the ego secret. |
| `-V`, `--verify` | `-s SUBJECT -i ISSUER -a ROLE [-d 'DEL,...']` | Submit one original native VERIFY request. No supplied leaves is valid for direct GNS resolution. |

`-P` sets PRIVATE on the newly stored record. `-F` and `-B` select resolution
directions for collect/verify; their default is both. Existing stored records
are fetched with INCLUDE_MAINTENANCE and retained with their original types,
flags, expirations and data. The replacement uses the service-returned canonical
label. The lookup and later replacement do not form a compare-and-swap operation
against concurrent editors. Only original STORE code0 is success.

DEL and ATTR use the existing shared two-pass `gnunet-gnsrecord-text` codec;
there is no extra grammar or signing implementation. DEL signed fields, including
case, Unicode and a subject role, remain intact. The official plural ABD IPC
cannot represent a subject role; verify rejects such a leaf before submission
rather than removing it. Signing and importing a singular DEL with a subject role
remain available. Returned leaf signatures/expiry are checked; reported chain
edges are labeled separately as unsigned source claims. A service `found1`
result is a terminal claim by the selected service, not independent CLI proof of
every GNS lookup or every graph derivation. `found0` prints a negative result and
returns failure. Unknown status, EOF, timeout and local cancellation never become
an authorization or a completed negative result.

For stores, `-T` accepts the existing standard relative-time grammar first, then
the PROGRAM absolute-time grammar, and `never`. Signing accepts only absolute
time or `never`. Bare absolute numeric timestamps follow the existing helper's
epoch-seconds convention; DEL text retains its exact u64 UTC-microseconds field. Signing does not convert a relative TTL into a credential timestamp.

One original `--timeout` (default120s) covers identity, text processing, lookup,
store/caller and output; no phase renews it. Endpoint choices are captured
coherently and then fixed. Every wait drives the same explicit Resolver and
checks the original native/canonical targets, signals and selected Logger. The original source is physically closed on cancellation/error, its actual
partial/whole exposure and already queued terminal facts are retained, and no
exposed mutation is replayed. Resolver and PROGRAM cleanup are independent.

No option accepts a private key. The IDENTITY secret is owned by a
zeroizing key, borrowed only by the existing purpose28 issuer or original native
request encoder, and dropped on every path. Codec work/results, collected leaf
transport and output buffers are zeroizing. Signed credentials on the ordinary
command line are public signed capabilities; the standard PROGRAM/OS argv is
not an erased secret storage API.

The `abd-command-rust` configuration section has finite resource settings:

| Key | Default | Range/meaning |
| --- | --- | --- |
| `OPERATION_TIMEOUT` | `120 s` | Finite original command lifetime; overridden by `--timeout`. |
| `OUTPUT_BYTES` | `1 MiB` | 1 through64MiB of stdout bytes/allocation. |
| `TEXT_BYTES` | `262140 B` | 1 through4MiB per shared codec input; scratch/output extent is max(TEXT_BYTES,65535). |
| `MAX_RECORDS` | `4096` | 1 through65535; native frames and the configured service impose their own exact limits. |
| `NAME_BYTES` | `253 B` | 1 through65535 for signed/resolved role bytes; a new NAMESTORE label is at most255B. |
| `UTC_UNCERTAINTY_US` | `0` | Conservative trusted UTC interval around the selected shared clock. |
| `ATTR_ALIGN64` | Native | Explicit official unpacked ATTR layout,4 or8. |

Storage, transport, codec, row metadata and output limits are independent finite
bounds; they are not an RSS measurement or a guarantee every maximum fits one
wire frame. Allocation and oversize failures are errors, never truncation. Stdout uses bounded synchronous writes and a flush. Its OS call cannot be
preempted by a native deadline; the same deadline is checked before/after calls,
and partial written bytes and successful flush are recorded separately. Chain
text is escaped. A canonical DEL containing unrepresentable terminal controls
is rejected rather than changing signed bytes or injecting output records.
