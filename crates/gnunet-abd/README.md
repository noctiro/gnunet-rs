# GNUnet ABD pure core

This no_std crate has explicit alloc algorithms and original PKEY/EDKEY
purpose28 signatures. It uses the official canonical signed DEL format and
restores the C plural IPC leaf serializer's omitted NUL before authenticating. Signed attributes remain original; normalized role comparison reuses the
existing Unicode18 lowercase+NFD implementation. Signed expiration and actual
GNS-record deadlines require a conservative caller UTC interval.

A Query resolves conjunctive and linked role rules by a finite least fixed
point. Terms of one authenticated ATTR record are AND for the same subject;
separate records are OR. A linked role uses the same intermediate
principal, rather than distributing a tail across different AND witnesses. Set-based intermediate deduplication and dense membership indices avoid
recursive/diamond path expansion. A concrete proof retains only earlier actual
facts; a cycle cannot authorize itself. Used original leaves and GNS edges
remain separately inspectable. Source authenticity is an explicit trusted
native GNS capability and is not established by constructing a Record struct.

One non-reused original lookup ID binds one original native token. Queued and
admitted work, result records and physical/logical lookup retirement
remain distinct. Cancellation retains every admitted original owner until its
retirement, without inventing a wire cancel or ACK, resetting a hard
deadline, or opening a replacement source. Native raw causes stay independently
owned by the host. Outcome is not cleanup completion.

Limits explicitly bound retained allocation capacity, principal/role/rule/fact
counts, supporting proof metadata, lookup owners and linked depth. Names and
metadata allocate on demand with fallible unpublished table growth. Temporary
allocation peaks and allocator process RSS are not measured or claimed. One
finite advancement may still inspect its configured bounded role/principal
profile; this is not a constant-time or performance acceptance claim. No
reported resource or source error becomes an authorization or a completed
negative query; expired/uncertain facts never provide authorization.

Known fixed-C differences are explicit: its input plural reader does not
authenticate signatures and drops subject roles; those restrictions are not
silently discarded here. Its backward precheck can accept an issuer match
without the requested subject, and refuses zero-input direct GNS proofs. The
Rust core requires membership of the exact requested subject and does
not manufacture a credential for a direct authenticated policy. Rich subject
roles remain supported in canonical signed GNS DEL; C leaf IPC cannot safely
transport them and rejects that profile. The fixed C ATTR header has an
unpacked uint64_t and requires explicit target layout4/8. The record-text plugin
exists in contrib source but is not installed by the active fixed Meson chain.

GNS/namestore collection and native client/service/CLI composition remain
required. No complete ABD or whole-library credit is granted.
