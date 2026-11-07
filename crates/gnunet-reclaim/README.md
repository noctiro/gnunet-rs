# RECLAIM objects and active IPC

Independent Rust codecs for the pinned official GNUnet revision. The default
build is allocation-free and uses borrowed views and caller-provided output. Attribute, Credential and Presentation have checked 80/48/48-byte prefixes;
validated lists apply explicit byte/item limits. Ticket capabilities use the
current variable-length GNS name, with a separate relying-party URI.

The IPC module covers all22 active messages961..982: attribute/credential
store/delete, three START/NEXT/STOP iterator families, ticket issue/revoke/consume
and their replies. General cancellation only suppresses the local
callback; no wire CANCEL or dormant REFERENCE operation is invented. Callers
must bind replies, end markers and raw status values to their original operations.

The optional `alloc` feature adds a shared bounded Pool and zeroizing immutable
owners. Quotas include vector capacities and owner metadata; typed views
borrow their original storage. Sensitive names, objects, tickets, URIs and key
views have redacted formatting. Borrowed noalloc buffers remain the caller's
responsibility to erase. Structural validation grants no cryptographic validity.

Credential/JWT/PABC semantics, presentation generation, convenience name
normalization, ticket business logic, persistence/resolver integration and native
client/service ownership remain in progress. This is not a complete RECLAIM
service or a claim of official C interoperability.
