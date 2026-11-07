# gnunet-namecache

The installed PROGRAM inspects or deletes the configured NAMECACHE entry for a
public zone and name. It uses the existing official NAMECACHE client and wire.

```
gnunet-namecache -c CONFIG -z PUBLIC_ZONE -n NAME
gnunet-namecache -c CONFIG -z PUBLIC_ZONE -n NAME -d
```

`-z/--zone` accepts the 58-character public PKEY/EDKEY identifier (the typed bare
zTLD). `-n/--name` is normalized by the existing NFC label utility before the
official query derivation. It must be nonempty UTF-8 without NUL and at most
1024 input bytes. `-d/--delete` submits the BLOCK_DELETE. The signed raw
result is printed: 1 removed, 0 absent, any other code is an error. A whole local
write alone never means that deletion succeeded. An absent lookup prints the
miss; it does not issue a DHT request or populate the cache.

Lookup ciphertext first passes the existing client's exact original-query,
carried-key signature and inner/outer expiration checks. Before display, the
existing pure block utility binds its signature key to the public zone
and normalized name, verifies that signature, decrypts and checks padded record
framing and current block expiration. Its existing applicable-record iterator
filters relative/expired records and suppresses inactive shadow fallbacks. Output includes the block's absolute microsecond expiry and each applicable
record's type number, type name when registered, absolute expiry and flag bits. The shared active record text codec supplies typed value formatting. Unsupported/corrupt value formats are identified as such with numeric type and
raw hex; they are not claimed to have a successful typed interpretation. This
does not turn arbitrary ciphertext into records or claim record values are
independently truthful beyond their signed zone/name provenance.

Standard PROGRAM configuration/help/version/log-level/log-file options use the
shared implementation. The selected Logger is shared through Reporter. One
LiveConfiguration, original broker/Resolver, SharedClock and runtime are used. `--namecache-socket PATH` selects an explicit Unix endpoint; otherwise normal
configured NAMECACHE CLIENT selection, including TCP through the same Resolver,
applies. `--record-profile native|little|big` selects the original producer's
host-order layout for the Messenger record formats which contain native fields;
the default is the current target's native NAME_MAX255 profile. It does not
guess a remote block producer from its connection or rewrite the signed bytes.

`--timeout-ms` defaults to 30000 and accepts 1 through 3600000. The original
logical target and independently captured native hard bound are retained across
polling and endpoint retry. The single operation has one immutable official RID
and private Rust token. Source attachment, queue admission, whole local write,
service completion and local cancellation remain separate report facts. There is no mutation replay after loss or uncertain exposure. Native guards run
before Resolver/canonical waits. SIGINT/SIGTERM, scheduler/clock/Resolver failure
or selected-log failure stops admission, cancels the original callback and
physically closes that exact MQ. The cancellation and remaining local
completion preserve Unsent/Partial/Written exposure; closing is no remote revoke.

On a callback the MQ is physically closed before interpretation/output. On all normal error paths it closes before completion-record drain and Resolver
disconnect. The shared foreground helper retains the original future even if
PROGRAM's scheduler exits, sets its same stop latch and polls its cleanup. The post-close local completion drain has one fixed five-second native bound;
it cannot create a new request or reuse an old RID. Operation/result, independent
cancel/drain/Resolver/stdout/log errors and successful cleanup reports remain
owned together. The final Resolver driver is dropped after disconnect,
including on a refusal. No worker, detached task or private key provider exists.

Plaintext, formatting buffers and staging are caller-owned zeroizing storage. The command permits one operation and one request frame, the official complete
frame bound, at most 2048 decoded records, 262140 bytes for a single formatted
value and 8 MiB total stdout. Output is ordinary synchronous bounded stdio;
blocking OS writes/flushes cannot be forcibly interrupted by a network deadline. Partial output or a flush error is retained as an output failure, never reported
as a complete display. Unknown/expired/malformed blocks are rejected by the
existing verification/open boundary. No key-file read/import, local private-key
fallback, service spawning, DNS/GNS resolution, protocol/plugin ABI or migration
format is introduced.

The public reference is GNUnet v0.29.1 commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`,
`src/cli/namecache/{meson.build,gnunet-namecache.c}`. Its installed `-z/-n/-d`
operations and true lookup/delete continuations are implemented here; bounded
resources, explicit field metadata and failure exit on local/decrypt/output
errors are Rust caller policy. The C tool's tendency to keep a successful exit
status for some missing/decryption diagnostics is not used as a success proof.

No Cargo/compiler/model,
program/help, crypto/key/entropy, socket/native, storage/worker or C path ran. Runtime interoperability and platform behavior are not asserted by this receipt.
