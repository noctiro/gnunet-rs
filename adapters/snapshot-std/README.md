# Shared snapshot storage

`gnunet-snapshot-host` stores opaque `Zeroizing<Vec<u8>>` bodies in isolated Rust
namespaces. Service codecs and business state stay in their own crates. The same
transaction code runs on Linux, macOS, FreeBSD and Windows through
`gnunet-native` original-directory and file operations.

## Public interfaces

```text
Store::open(namespace, directory, backend::Limits) -> (Store, Loaded)
Store::commit(expected_generation, zeroizing_body) -> Committed
Worker::start(Store) -> Worker
Worker::submit / poll / request_stop / shutdown / poll_join
```

`Loaded` transfers its body once. `Loaded` and `Committed` have private
constructors and report the original namespace, generation and `directory_sync`
capability. The optional worker admits one bounded outstanding command/result;
its job and completion bind the original worker and checked serial. A caller may
instead run synchronous commits from its existing owned worker.

## Namespaces and format

| Namespace | Marker | Snapshot | Lock | Outer magic |
| --- | --- | --- | --- | --- |
| Identity | `.identity-rust-store` | `identity.snapshot` | `.identity-rust.lock` | `GNIDST01` |
| Namestore | `.namestore-rust-store` | `namestore.snapshot` | `.namestore-rust.lock` | `GNNMST01` |
| Revocation | `.revocation-rust-store` | `revocation.snapshot` | `.revocation-rust.lock` | `GNREV001` |
| Oidc | `.rest-oidc-rust-store` | `rest-oidc.snapshot` | `.rest-oidc-rust.lock` | `GNOIDC01` |
| Messenger | `.messenger-rust-store` | `messenger.snapshot` | `.messenger-rust.lock` | `GNMSG001` |
| Hostlist | `.hostlist-rust-store` | `hostlist.snapshot` | `.hostlist-rust.lock` | `GNHOST01` |
| Transport | `.transport-rust-monotime-store` | `transport-monotime.snapshot` | `.transport-rust-monotime.lock` | `GNTRNS01` |
| TransportDv | `.transport-rust-dv-store` | `transport-dv.snapshot` | `.transport-rust-dv.lock` | `GNDVST01` |
| TransportTcp | `.tcp-rust-replay-store` | `tcp-replay.snapshot` | `.tcp-rust-replay.lock` | `GNTCPS02` |
| GnsPublication | `.gns-publication-rust-store` | `gns-publication.snapshot` | `.gns-publication-rust.lock` | `GNGNSP01` |


Markers and pending names are fixed per namespace. Known foreign markers are
refused before interpreting private bytes or creating this namespace's lock.
The envelope remains 88 bytes: magic, big-endian generation/body length and a
512-bit checksum over the header prefix and body. The body cap is 64 MiB,
default 4 MiB. These private formats are independent of C databases; there is no
legacy import, migration or silent reset.

## Initialization and transaction contracts

The parent must exist; `TransportTcp` additionally requires a private parent to
protect replay-ledger naming authority. `Store::open` prepares a private sibling
containing the complete flushed marker and held writer lease, then publishes the
whole directory without replacing an existing entry. Losing concurrent creators
retire only their own original marker, lock and empty staging directory. Stale
sibling stages are never adopted or recursively removed. Existing unmarked,
malformed or foreign stores are refused unchanged. `GnsPublication` retains its
bounded `initialization-pending/NotReady` response for a missing existing marker.

An existing marked directory without an image reports generation 0 and
`created_directory=false`; service-specific authorities decide whether that is
legal. Original directory, marker, lock and image handles remain pinned and
revalidated. Files must be private, ordinary and single-link. Unix checks the
effective owner/mode; Windows checks the process-user owner and restrictive DACL.
Final symlinks and name-surrogate reparse points are refused.

Commit requires the expected generation, a bounded pending write and an actual
file flush and writer close before replacement. Commit and reopen verify the
exact header and body in chunks through the same retained read-only file. Unix
completes directory synchronization. Windows flushes the renamed original
through a separate identity-checked handle and reports
`DirectorySync::Unavailable`. Recovery combines its store and parent directory
barrier results. An attempted publication or
lost fence reports `Unknown` and permanently stops this writer. The first cause
and independent cleanup error are retained, with any unresolved original file.

Namespace administration must be serialized by cooperating owners. Linux and
macOS use kernel no-replacement rename; Windows uses captured-handle rename.
FreeBSD serializes cooperating publishers with an independently opened original
parent lock across its destination check and rename. This is not protection
against a hostile same-user namespace racer.

## Ownership and source layout

`backend.rs` holds the store and receipt types. Its `namespace`, `initialize`,
`open`, `image`, `commit` and `failure` modules separate fixed formats, complete
initialization, recovery/fences, envelope encoding, publication and error facts.
Native syscalls and filesystem-specific behavior belong in `gnunet-native`.

Canceling a wait preserves the original job/channel/cursor. Shutdown closes
admissions, drains completions and joins the original thread. An admitted
filesystem syscall cannot be force-canceled; emergency worker Drop also joins.
The kernel may block, and file Drop supplies no separate close-error receipt.
