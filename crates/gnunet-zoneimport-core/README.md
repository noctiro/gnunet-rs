# Online DNS import business owner

This crate supplies bounded DNS-to-NAMESTORE scheduling and public DNS record
conversion. The default `no_std` profile exposes coordinate/policy types and the
allocation-free converter. The explicit `alloc` feature adds `Core` with bounded
fallible metadata pools. Initial name/zone reservations are at most 1024/64
rows; inserting a row grows its pool fallibly within the configured hard cap. Reservation precedes string-byte accounting and row insertion, so failed growth
does not spend the name-byte quota or create a partial row. The job pool remains
fixed. It has no OS, executor, socket, IDENTITY client,
NAMESTORE client, storage worker, secret-key or facade dependency.

Internal `BTreeMap` indexes provide logarithmic name/zone deduplication and
exact cache-name lookup. Rows and their index keys share the same `Arc<str>`;
the name-byte quota counts each retained string once. Cache lookup constructs
only a bounded stack FQDN, with unrelated/non-DNS labels remaining non-matches. Fallible quota/String/row reservation is completed before committing indexes,
rows or byte counts. `Arc` and standard B-tree node allocations retain Rust
`alloc`'s global OOM boundary; this is not a claim that every allocation failure
can be returned or cancelled. There are no new dependencies or public capacity
APIs, and row/name-byte hard caps remain independent of input reserve hints.

The caller supplies initial EGO observations, their public keys and the
inventory END, then adds canonical IDNA ASCII FQDNs and seals input
EOF. Names are case-insensitively deduplicated. Each first label is imported
under its suffix control zone. The nearest existing suffix ego is an independent
namespace anchor; an exact existing control ego is used directly without
reparenting it or repairing its upstream delegation. Only missing layers below
that anchor are created parent-first. An absent ancestor is a failed name, not a
fabricated root identity. Child CREATE and parent delegation are independent
facts exposed by `zone_facts`; selecting an existing anchor does not claim that
its parent was observed or stored.

For a child actually created in this instance, the complete parent-label
lookup can reuse one matching live delegation. Empty, foreign, expired or mixed
observed sets otherwise proceed to the normal standard raw32 replacement with
relative one-week expiry, matching the public tool's parent update behavior. There is no policy requiring global consistency of every inventoried parent
graph. The lookup and STORE remain separate operations with no compare-and-swap
or cross-service transaction claim. Only original STORE code0 records
`parent_stored`; an unknown mutation fences that name or zone. Possessing the
child key cannot repair an unknown parent STORE.

An failed parent lookup uses clock-free `delegation_failed` only after
its original native owner has settled/closed; the host keeps the cause. It does not substitute an empty observation or a mutation Unknown, and does not
claim that the parent was stored. Other zones may continue independently.

Real per-zone iterator attempts establish the initial cache observations. Relative lifetimes are
converted using the supplied canonical sample, with GNUnet's saturating FOREVER
record-data arithmetic. DNS scheduling begins after every relevant attempt is
terminal, not only after successful ENDs. `ZoneFacts.cache` explicitly reports
`Unused`, `Pending`, `Complete` (END), or `Incomplete` (settled failure). The degraded policy preserves previously observed sets and their expiry;
unseen names query fresh DNS. Failure remains an independent failed completion
and host-owned original cause; it never claims a complete snapshot. The supplied
host must bind every scan item to its original zone
and project its returned label through the same IDNA profile.

`next_action` borrows one retained payload. The host copies what it needs before
awaiting, records `admitted` only after native admission, and reports only
the same original job's result. Capacity backpressure uses `defer`/`resume`
without resetting its bounds. IDs include a private per-Core allocation brand;
the diagnostic integer is neither a constructor nor a completion receipt.

Each IN NS query has one finite `Bounds`. UDP, any TC-triggered TCP fallback and
the subsequent replacement STORE share those original targets. The converter
checks a complete matching question before TC fallback, and requires a complete
matching NOERROR final response before generating a replacement. NXDOMAIN,
other RCODEs, malformed/truncated final responses and unsupported-only data are
failures that preserve old records. A genuine empty NOERROR answer produces an
empty replacement and a default one-day refresh.

Answer bytes remain host-owned under the original `AnswerId` until a terminal
`Completion.release`. Only original NAMESTORE code0 advances stored
counts and the TTL schedule; queue admission and whole local writes do not. Known rejection or physically settled unsent work can schedule a new DNS query,
never replay the old mutation. Unknown STORE results do not automatically retry. Metrics are cumulative saturating business observations, independent of native
packet, IPC, authentication and durability facts.

`Times` keeps canonical absolute time separate from a nondecreasing elapsed
coordinate. The host maps `Bounds.until` through its one original native epoch
and checks its OS deadline before I/O. `minimum_expiration = FOREVER` is
legal record data; it creates no infinite query/STORE budget or giant native
sleep. `next_wakeup` omits FOREVER data and blocked name timers when all job
credits are occupied; deferred/active native operations register their real
wakes in the host.

`stop` permanently prevents new work. `next_retirement`, result callbacks and
retirement receipts are clock-free so a failed clock does not discard a
known native result or prevent physical cleanup. Expiry requests retirement and
retains credit until the original owner is actually settled. `quiescent` means
only that Core has no tracked jobs; the host must separately finish its original
clients, subscriptions, sockets, workers and retained output/unknown reports.

The production contract is based on pinned GNUnet 0.29.1
`src/cli/namestore/gnunet-zoneimport.c`: stdin EOF before continuous TTL refresh,
IN NS queries, first-label/suffix ownership, zone iteration, relative
parent delegation, pending STORE exclusion, retries and three-section result
conversion. This source candidate was only formatted and reviewed as text; it
does not assert DNS/network, cryptographic, mixed-node or storage execution.
