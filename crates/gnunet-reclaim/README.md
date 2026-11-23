# RECLAIM objects and active IPC

Independent Rust codecs for the pinned official GNUnet revision. The default
build is allocation-free and uses borrowed views and caller-provided output. Attribute, Credential and Presentation have checked 80/48/48-byte prefixes;
validated lists apply explicit byte/item limits. Ticket capabilities use the
current variable-length GNS name, with a separate relying-party URI.

The IPC module covers all 22 active messages (961–982): attribute/credential
store/delete, three START/NEXT/STOP iterator families, ticket issue/revoke/consume
and their replies. General cancellation only suppresses the local
callback; no wire CANCEL or dormant REFERENCE operation is invented. Callers
must bind replies, end markers and raw status values to their original operations.

`fixed::Store` prepares an attribute or credential NAMESTORE record. It retains
the original private authority and RID, and accepts a fresh identifier only
when the request carries zero. The caller supplies entropy, checks collisions,
and commits the record before replying.

`fixed::Delete` plans attribute and credential deletion from one private-zone
snapshot. It removes the complete target label, closes dependent credential
links, and filters references and presentations whose objects no longer
survive. The caller supplies the active projection and original row identities,
then commits the resulting transaction before replying.

`fixed::Issue` checks an exact attribute selection against the caller's record
and byte limits. It either matches an active ticket for the original zone and
relying party or prepares one NAMESTORE row using caller-provided credentials
and entropy. The service must encode the complete result and wait for the
authoritative commit before sending a new ticket.

`fixed::Cursor` reads normalized NAMESTORE rows from one private zone in serial
order. START and each NEXT grant one response. The caller bounds each scan turn,
owns partial writes, and emits END only when the authority reports exhaustion.

The optional `alloc` feature adds a shared bounded Pool and zeroizing immutable
owners. Quotas include vector capacities and owner metadata; typed views
borrow their original storage. Sensitive names, objects, tickets, URIs and key
views have redacted formatting. Borrowed noalloc buffers remain the caller's
responsibility to erase. Structural validation grants no cryptographic validity.

See [RECLAIM business operations](BUSINESS.md) for the provider and storage
contracts.
