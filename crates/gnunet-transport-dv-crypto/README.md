# DV boxed-payload cryptography

Allocation-free GNUnet DV BOX cryptography. The caller supplies verified peer
identity, entropy, clocks, original task lifetimes and bounded buffers.

## Source and packet lifetime

`Instance::source` binds one local identity and original allocation to a hard
deadline. Each `Task` carries a fixed source-monotonic stamp and deadline.
`Source::retire` invalidates the allocation and all its tasks. The embedding
owns native source observation and retirement.

`Task::prepare_seal` derives the official DHKEM material and draws the
XChaCha20-Poly1305 nonce from the supplied entropy source. The purpose-30
signature binds the local sender, original target, stamp and encapsulation.
`seal_local` signs using the matching local EdDSA key. `seal` verifies a
signature from the original external signer before encrypting the official DV
payload and encoding its BOX envelope.

`Task::prepare_open` accepts a final-hop BOX. `RecipientKey::new` checks the
X25519 scalar against the target's EdDSA identity. Local and trusted provider
opening validate the AEAD tag, complete inner frame, nesting rules and sender
signature before producing `Opened`. Its metadata is authenticated. Its
plaintext loan stays tied to the original task and is erased on drop or
recycle. Use the `open_recover` variants to recover an erased buffer after
failure.

## Reuse key material

`PreparedSeal::certify` and `certify_local` produce `SendMaterial` for a
fixed sender, target, encapsulation, signed stamp and expiry. Each packet
gets its own task and nonce. The nonce combines a random 16-byte prefix with
a checked 64-bit counter. Any attempt that starts encryption consumes its
nonce. Expiration and message limits remain fixed during reuse.

`ReceiveMaterial` binds the local source, target, encapsulation and expiry.
Every packet gets a fresh AEAD check. Only a matching sender, stamp and
signature under that encapsulation can reuse the signature verification.
Caller-owned cache slots bound storage and carry generation-specific handles.
Replacing or clearing a slot erases the retired key.

## Replay admission

`replay::Replay` claims the original live source and uses caller-provided
watermark and nonce tables. The exact tuple is the local target,
encapsulation and nonce. An older signed stamp is refused. Equal stamps may
carry distinct tuples. Probe budgets bound table lookup work. A full table
preserves earlier entries and refuses new packets. Dropping the owner
preserves the rows until explicit source retirement and cleanup.

`replay::durable::Destination` binds a synchronous `Store` to one original
source. The store receives authenticated metadata and commits the sender
floor and exact tuple in one durable operation. A successful commit issues a
`Granted` plaintext loan. An uncertain commit retires the original source
and requires recovery of its storage authority before a new source starts.
Known storage rejection returns the unchanged authenticated owner.

The caller drives forwarding, application admission and native completion.
An admitted packet can still expire or lose its original source before it is
delivered. Retirement or buffer recycling leaves the recorded replay history
in place for its owner's retention policy.
