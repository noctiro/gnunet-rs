# GNS resolver core

`gnunet-gns` owns recursive GNS authority and record decisions. It has no socket,
scheduler, C ABI, native transport, or implicit DNS fallback. Default `no_std`
builds expose allocation-free Start Zone selection. `alloc` adds a bounded
multi-query `Resolver` with fallible allocation and explicit local policy.

For each admitted query, retain `QueryId`, read its original `Effect`, and return
the matching typed receipt. Effect IDs are instance-branded and never reused. Cancellation invalidates all authority and nameserver children immediately. Transport retries may reread an effect but must retain its original identity. `failed` supplies dependency exhaustion/deadline; no operation succeeds merely
because an action was issued. Completed results are owned records or
explicit `Failure` values and remain admitted until `take_result`.

The core authenticates original encrypted bytes with the requested zone and NFC
label before decrypting them. Every authority first requests a revocation check. Invalid remote candidates retain their original GET while consuming finite work. Cached corruption obeys the same remote policy as a cache miss. Delayed cache
store receipts re-open the block using current UTC, including shadow selection.

Dependency ports cover revocation, encrypted cache read/write, encrypted remote
storage, symbolic service mappings, recursive DNS, and default-system name
resolution. GNS nameserver dependencies use internal frames and the original
query's shared budgets. External DNS/system adapters must charge recursive work
using `spent` and obey the effect's allowance. DNS effects are DNS-only and must
validate the DNS transaction/server/question before returning records. Their records carry a DNS origin; they never become GNS-authenticated records. No concrete port implementation or network interoperability is claimed here.

`lookup_name` NFC-normalizes application input and configurable suffix mappings;
the no-allocation `select_start_zone` helper accepts already-canonical names. Configured resource ceilings are local policy, not DNS/GNS global length rules. `Policy::from_local_options` bridges the public IPC enum without adding a client
or generic wire dependency to this domain crate. The external service layer can
translate `gnunet-client::gns::Lookup` parameters to `Lookup` and serialize
returned `Record::as_data()` with the existing official result codec.

NICK publication belongs to namestore/publication; its result gating belongs
here. VPN address mapping belongs to a DNS bridge/client adapter. Numeric address
interpretation is an explicit `address_literal` application convenience.

This implementation covers a pure recursive owner with abstract effects. It does not
claim a native GNS server, full GNUnet node, completed application adapters,
standards certification, or benchmarked performance. The pure tests use actual
Rust PKEY/EDKEY-signed encrypted blocks and record payloads. See UPSTREAM.md
and the independent requirement/test matrix for exact scope and differences.

The pure resolver can explicitly enable a single optional near-expiry cache
refresh hint. It is disabled unless an independent background owner is supplied. An authenticated, currently valid cache block with less than five minutes left
and an remote-allowed policy yields only owned zone/label/query/expiration
metadata; it contains no foreground QueryId/EffectId. Foreground processing and
result delivery continue normally. An occupied hint slot or fallible label-copy
refusal drops only optional work. The already-verified block supplies expiration
without a second signature verification. Candidate validation has its own finite
work count and requires an exact authenticated, decryptable, strictly fresher
block; the normal native service owns admission, time and cache updates.
