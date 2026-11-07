# GNS reference sources

Primary documents consulted for this implementation:

- [RFC9498](https://www.rfc-editor.org/rfc/rfc9498.html), especially §§5,7,8.
- [LSD0008](https://lsd.gnunet.org/lsd0008/), especially §§3–4 (SBOX extension).
- [Current GANA record registry](https://gana.gnunet.org/gnu-name-system-record-types/gnu_name_system_record_types.html).

The C source reference is GNUnet v0.29.1, commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`,
`src/service/gns/gnunet-service-gns_resolver.c`.

Deliberate choices relative to that C source:

| Area | Candidate behavior and reason |
| --- | --- |
| Unknown critical values | Fail explicitly, including unassigned65546 and unsupported FAESTKEY; C's terminal default/plugin classifier is insufficient. PKEY and EDKEY are the supported zone constructions. |
| GNS2DNS mixed sets | Accept DNS security records and ignore supplemental records for authority selection; require consistent namespace. The C resolver's1859–1867 rejects mixed sets despite its RFC FIXME. |
| Relative/absolute REDIRECT | Preserve unresolved left labels. Direct typed-zTLD continuation implements the same GNS target without a roundtrip through OS configuration. |
| Stored CNAME | `follow_cname` is explicit: true supplies GNUnet's system-resolution convenience using the CNAME target alone (replacing any remainder); false returns ordinary final CNAME data. DNS effects never reinterpret DNS CNAME as GNS. |
| NO_DHT intent | LocalOnly is enforced on every GNS cache fallback and child, including corrupted/disabled cache. C's3032–3050 and3082–3085 bypass its own documented policy. |
| NICK | Apply supplemental query-type gating on the final set; publication remains outside the resolver. |
| Shadow expiry | Existing Rust crypto applies same-type suppression and checks singleton shadow expiry correctly; the C loop misses the singleton expired shadow case. Expiry equal to remains valid in the existing crypto profile. |
| Work/lifecycle | Checked counters, branded effects, authority budget and total work are Rust ownership policy. No C scheduler, callback order, wrapping counters or heap layout is copied. |
| Cache strategy | Cache-first and optional store are implemented. Proactive near-expiry refresh is omitted as an internal performance strategy; optional cache insertion cannot consume an already valid final lookup. |

Concrete DNS recursion, cache storage, revocation storage, default-system
resolution and remote-storage transport are dependency adapters. This implementation
does not certify their implementations or borrow unrelated C-process evidence.
Its own new tests run no sockets and no C processes. Source/test hashes and
44-item status mapping are recorded in the enclosing candidate report.
