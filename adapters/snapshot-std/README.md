# Shared qualified raw snapshot storage

`gnunet-snapshot-host` owns opaque `Zeroizing<Vec<u8>>` bodies and filesystem/worker receipts. It depends on no service client, Resolver or business key type. Callers interpret and bound their own format. They can use synchronous `Store::commit` from an existing owned worker, or the optional explicit snapshot worker; no per-request task or hidden service is created.

```text
Store::open(namespace, directory, backend::Limits) -> (Store, Loaded)
Store::commit(expected_generation, zeroizing_body) -> actual Committed
Worker::start(Store) -> Worker
Worker::submit / poll / request_stop / shutdown / poll_join
```

Loaded and Committed have private constructors and retain the namespace/generation. Loaded transfers its erased body once. Worker Job/Completion bind the original worker and checked serial; Stopped exists only after join. Worker admission has one bounded outstanding command/result.

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

Namespaces have fixed distinct marker payloads and recognized temporary names. A known foreign marker is rejected before any private body is interpreted or this namespace's lock is created. Callers never import an unrecognized existing directory or temporary image. The generic store does not parse or log keys, records or labels.

Every fresh ordinary namespace holds its writer lease before publishing its complete synchronized marker and keeps that lease in the returned Store through the caller's initial commit. A competing opener cannot take that lease and consume the creator's unique new-directory authority. Marker publication uses a separate create-new file, file sync and atomic rename, so an opener sees no partial marker. TransportTcp retains its separately qualified atomic directory publication. An existing unmarked/foreign directory is never adopted or modified: GnsPublication returns `initialization-pending/NotReady` for its original bounded nonce wait, while other ordinary namespaces retain their existing refusal. A present malformed marker remains an error. Store reports an existing marked directory without a canonical image as generation0/created=false; the nonce and OIDC authorities explicitly reject that state instead of resetting history or keys. Caller-specific initialization and refusal policy remain in those owners.

Directories/files retain private owner/mode, no-final-symlink, regular/single-link, exclusive writer lease and original inode fences. Store creates the final directory; a caller may create only missing parents. Successful commit requires the original generation, temporary write, file sync, atomic replacement, directory sync, same-inode readback/checksum and final fence. Original stage/errno and independent temporary cleanup errors remain available. Attempted publication or fence loss is Unknown, never rollback. Body size is capped64MiB, default4MiB.

Canceling a wait preserves original channels/job/cursors. A caller stops admissions and closes its own MQs; it cannot force-cancel an admitted fsync/rename. Worker shutdown drains completions and joins the original thread; emergency Drop also joins, without manufacturing its discarded final result as a success receipt. Synchronous filesystem progress may block in the kernel, and File Drop exposes no extra close errno. The namespace model assumes cooperating same-UID owners, not a hostile same-UID path racer.

These private Rust storage formats are independent of C databases and external GNUnet protocols. No legacy private-state migration or silent reset is provided. Source and selected compilation do not establish namespace denial, persistence, concurrent initialization or official interoperability acceptance.
