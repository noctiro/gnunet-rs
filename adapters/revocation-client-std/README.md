# Official REVOCATION native client

`gnunet-revocation-client-host` owns one QUERY or REVOKE and one dedicated original Unix/TCP CLIENT MQ. `Client::query`/`revoke` take a stable caller `Instance`, explicit `EndpointSource`, original absolute `Deadlines`, and finite frame/syscall `Limits`. Construction snapshots the selector and reserves one original clock subscription; it opens no socket, Resolver, or task. `poll`/`drive` preserve original cursors when their future is dropped. The source's clock and Resolver remain caller-owned.

`Connected`, immutable `Queued`, whole local `Submitted`, actual `Reply`, and physical `Ended` are separate observations. QUERY raw0 means revoked and raw1 means valid. Actual pinned service REVOKE raw0 means accepted and raw1 means failure; the public C header's contrary comment is not normalized into success1. Unknown numeric statuses remain raw. The exact8-byte response must have the expected message kind and follow the full original request. No wire RID, CANCEL, ACK extension, or extra proof validation exists here.

Cancel/close/drop physically stop the dedicated original MQ independently of clock progress. An exposed REVOKE that lacks a reply has an unknown service outcome. It is never replayed. Preattachment connection attempts may retry only within the original send bound. Native send/reply guards are registered and enforced before waiting for a coherent logical clock sample, so clock revision races cannot extend their original hard limit. The shared native transport closes by ownership and exposes no independent close errno; this adapter does not invent one.

One immutable outbound frame and one bounded inbound frame are retained. Default maximum is380 bytes and the default syscall quantum380. The `Instance` uses checked allocation IDs, so bounded fresh jobs can share a stable domain while old tokens remain distinct. The public certificate/key bytes here are not secret; this adapter does not obtain any private signing material.

The ignored `tests/original_mq.rs` is one prepared controlled Unix IPC ownership model: a7-byte reply remains incomplete until the original deadline physically closes that MQ, then a distinct fresh job receives raw QUERY0. This package has only been parsed/formatted with rustfmt, not qualified against a C service or process profile.

Central integration registered the SDK/CLI/foreground and passed affected all-target/all-feature strict compilation plus SDK/architecture checks.
