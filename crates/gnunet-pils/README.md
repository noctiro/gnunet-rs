# Peer identity lifecycle

This allocation-free owner implements PILS1831..1838 service decisions: initial
empty-context identity, signed HELLO updates, unsigned address feeds, exact
purpose-region Ed25519 signing, X25519 DHKEM decapsulation and legacy hashed DH. The host owns connections, queue admission, clocks and persistence. Encoded output is not a remote acknowledgement or durable write.

`MasterKey` owns the persisted initial32 bytes. `ActiveIdentity` owns current
signing/exchange keys. Neither is cloneable or printable. The explicit
`with_active_seed` callback constructs separate CORE/TCP key owners without
exporting the master seed. Identity rotation requires dropping old borrowers
and their service epochs before publishing new keys. Crypto IPC result buffers
are secret data and must be erased by their transport owner.

Profiles are explicit and never tried as fallbacks. Normal v0.29.1 uses an empty
address hash and `gnunet-pils-ephemeral-peer-key`. The official conditional build
hashes canonical address strings. Its signatures cover those addresses; normal
signatures cover metadata only. The July2025 [LSD0014 text](https://lsd.gnunet.org/lsd0014/)
instead says `gnunet-pils-contextual-peer-key`, while its published derived-key
vector matches the source's ephemeral label. `Lsd0014Text` records the textual
algorithm separately. A regression retains this discrepancy explicitly.

`client::Client` adds the typed sans-I/O client boundary for all eight IPC
messages. It owns bounded immutable crypto requests, original wire request IDs,
per-MQ epochs and one output byte lease. Its caller-provided non-ZST `Instance`
is exclusively borrowed; operation, epoch, identity and transmit capabilities
from another instance are rejected even when their diagnostic values collide. Wire IDs are never reused in this owner's lifetime. After 2^32 crypto admissions,
new work returns `Overflow` while existing operations can complete/replay. A host
may explicitly close/report pending IDs, close the physical MQ and construct a
new owner; no private wire extension or silently dropped operation is used.

Sign/DH/KEM can be admitted while disconnected. MQ loss retains their original
bytes and IDs for replay on the next MQ. Unknown, canceled or duplicate results
are dropped; malformed known frames and wrong response families are refused. Well-framed unregistered message types follow the official MQ's ignore rule. Cancellation suppresses only the original completion/replay. It cannot remove an
already copied/partially written frame: the host must finish that original lease
or close its MQ. `written` is a local full-write fact, not server processing. FEED has no response ID or acknowledgement: it is admitted only with an active
MQ, completes local submission on full write, and is not replayed automatically. MQ loss reports whether each pending FEED was uncopied or had unknown submission.

Announcements are checked structurally, for the exact selected HELLO signature,
expiry at caller UTC, and address hash. Current identity/local-key authority is
invalidated on MQ loss; retained public announcement bytes are only cache data. Optional caller-owned `MasterKey` produces a private key only when its derived
public identity matches. `LocalKeyStatus::Mismatch` is explicit and service
requests remain available. Matched local key borrows prevent simultaneous
rotation; `with_active_seed` constructs another deliberately owned key without
publishing master material. The source and LSD0014-text labels never fall back.

`KeyTarget::ServiceCurrent` returns the key used by the service at processing. Signature results independently verify the exact retained purpose region and
return the signer; they do not replace current identity. `Exact(identity)`
binds the public key, rather than treating an old local revision as a wire tag. DH/KEM responses have no peer field: their identity is only the last verified
announcement on the **same ordered trusted MQ**. The host must preserve that order
and retire the MQ on announcement/protocol errors. This observation is no global
authorization or independently verified secret-key identity. A changed Exact
key fails the original request and erases its result; ServiceCurrent explicitly
accepts the observed new context. `sign_hello` uses the official purpose7 region. The reference service rejects a header-only signature purpose; the typed client
refuses it before submission without reproducing its erroneous `ntohs(size)`
checker or weakening structural wire validation.

Every `receive` consumes a mutable complete frame and erases it on **all** return
paths, including stale epochs, unknown/canceled secret results and malformed
frames. Successful secrets transfer into separate `Secret<N>` owners erased on
drop, with no Clone/Debug/serialization. Host framing must pass only that exact
frame so coalesced tails remain intact. Outbound copied buffers remain host-owned.

The default client remains allocation-free. The optional `alloc` feature adds
sealed `HeapBytes` backing and `HeapClient`: the same state machine and owner
checks retain actual-length zeroized requests and announcement bytes. The slot
array bounds metadata rather than embedding maximum-size payloads per slot. Allocation refusal is explicit and precedes admission/publication. Inline
backing remains the default and keeps the Cortex-M0/M4 no-allocation boundary. `next_request_len` permits a native host to reserve immutable output storage
before taking the original byte lease; it grants no new completion authority.

Native hosts can separate loss invalidation from retry-clock registration:
`prepare_connection_lost` revokes old authority and reports original FEEDs,
while the host later samples the canonical clock and calls `register_retry`. During that interval
no new MQ can begin. A clock refusal cannot keep an already retired physical
MQ's identity active or silently discard the original logical work. The existing
combined sans-I/O methods preserve their original semantics.

The pure package has no native connector, Resolver, timer, partial-stream host,
persisted identity loader or daemon loop. `gnunet-pils-host/client` implements
the native client boundary separately. Its independent `service` feature and
`gnunet-service-pils` compose this existing service owner with shared bounded
Unix/TCP framing, configured startup/activation and fenced durable raw32 private
roots. All private-file synchronization occurs at the explicit startup boundary,
with stream retirement preceding key erasure and lease release. Active
reference service semantics have no periodic identity/HELLO task: startup and
FEED produce updates. Native composition supplies no new protocol or C backend.

Pure-core, production-host models, native Rust compositions, normal-C direct and
controlled-loss runs retain separate source-bound evidence scopes; none alone
establishes independent whole-Node status. Malformed FEED refusal and safe exact
purpose validation remain explicit differences from erroneous reference input
handling, without weakening valid official messages or inventing private fields.
