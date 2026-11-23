# GNS resolver core

`gnunet-gns` owns recursive GNS authority and record decisions. It has no socket,
scheduler, C ABI, native transport, or implicit DNS fallback. Default `no_std`
builds expose start-zone selection and a fixed resolver. The `alloc` feature
adds a resolver with fallible allocation and explicit external dependency ports.

## Public interface

### Fixed resolver

Use `fixed::Resolver` for caller-owned query slots, one reusable plaintext
workspace and a reply body supplied by the caller. Each authority requires its
own revocation receipt before NAMECACHE and DHT lookup. The resolver handles
PKEY and EDKEY delegation and GNS-local aliases and returns the serialized
record count and body length. The embedding keeps the reply until its native
writer settles and retires the exact dependency on cancellation. External DNS
and system lookup use explicit providers. BOX and SBOX share the same original
prefix selection as the allocating resolver. Fixed resolution uses GANA
assignments and numeric service ports. An optional `BoxRegistry` supplies
additional protocol and service names from the embedding's prepared registry.

`Resolver::with_dns_policy` sets whether a lookup may follow GNS2DNS or an
alias outside GNS. `DnsPolicy::Deny` still permits direct reads of delegation
and alias records. The allocating resolver uses the same policy in `Limits`.
In `fixed::Instance<Q, B, C, A>`, `Q` counts query slots, `B` counts shared DNS
bridge slots, `C` is the byte capacity for server targets in each bridge, and
`A` bounds distinct live addresses for each selected server. Each bridge
also reserves 4 KiB for DNS security records. Targets and their addresses are
tried in order. A delegation or server whose data exceeds a storage budget
cannot expose a partial set. If no alternative succeeds, the lookup reports
`Failure::Fault(Error::Capacity)`.

### Allocating resolver

For each admitted query, retain `QueryId`, read its original `Effect`, and return
the matching typed receipt. Effect IDs are instance-branded and never reused. Cancellation invalidates all authority and nameserver children immediately. Transport retries may reread an effect but must retain its original identity. `failed` supplies dependency exhaustion/deadline; no operation succeeds merely
because an action was issued. Completed results are owned records or
explicit `Failure` values and remain admitted until `take_result`.

The core authenticates original encrypted bytes with the requested zone and NFC
label before decrypting them. Every authority first requests a revocation check. Invalid remote candidates retain their original GET while consuming finite work. Cached corruption obeys the same remote policy as a cache miss. Delayed cache
store receipts re-open the block using current UTC, including shadow selection.

Dependency ports cover revocation, encrypted cache read/write, encrypted remote
storage, protocol and service mappings, recursive DNS, and default-system name
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

The pure recursive owner emits explicit effects. The
[native GNS host](../../adapters/gns-service-std/README.md) supplies providers and
service I/O. See [reference behavior](UPSTREAM.md) for format and validation
differences.

The pure resolver can explicitly enable a single optional near-expiry cache
refresh hint. It is disabled unless an independent background owner is supplied. An authenticated, currently valid cache block with less than five minutes left
and an remote-allowed policy yields only owned zone/label/query/expiration
metadata; it contains no foreground QueryId/EffectId. Foreground processing and
result delivery continue normally. An occupied hint slot or fallible label-copy
refusal drops only optional work. The already-verified block supplies expiration
without a second signature verification. Candidate validation has its own finite
work count and requires an exact authenticated, decryptable, strictly fresher
block; the normal native service owns admission, time and cache updates.
