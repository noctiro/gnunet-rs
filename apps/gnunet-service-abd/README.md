# Ordinary ABD SERVICE

The ordinary installed executable/endpoint is gnunet-service-abd/[abd]. Standard
startup/options/inherited descriptors, configured process identity, bound
listeners, shared selected Logger/Clock/Resolver, signals and parent control use
the existing SERVICE facilities. RUN_PER_USER is the official deployment; Rust
selects same-UID/GID admission by default where abd.conf declares neither field. Normal UNIX_MATCH_UID/GID overrides stay explicit. READY means IPC admission,
not connected GNS/NAMESTORE or an authorized request.

The native owner preserves multiple original RIDs per MQ, query/proof
sources and output dispositions. Client closure retires that original MQ
before cancelling its original query owners. A negative result requires actual
source/proof completion; timeout, source loss and bounded-resource refusal do
not fabricate an authorization or a completed negative answer. A result is only
counted when that exact original IPC frame really writes in full.

[abd-service-rust] configures finite client/query/aggregate reservations, actual
first/partial/operation/output/shutdown bounds and trusted-clock uncertainty,
pure proof node/rule/term/depth/fact/witness/lookup/name/credential capacities,
explicit ATTR_ALIGN64 and GNS/PRIVATE NAMESTORE/Resolver resources. The
process shares4096 bounded clock subscription slots; failed reservations are
resource errors. No profile or source error silently replays old work.

This source is not installed/compiled yet and depends on the author's
native Server and verified-forward core feed. No native/runtime/crypto/C
interoperability, measured RSS/performance or complete ABD capability credit.
