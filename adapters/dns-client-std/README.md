# Official DNS interception client

This is DNS service IPC, not the DNSSTUB external UDP resolver. It sends INIT flags, retains opaque eight-byte callbacks from one MQ, and sends only official Drop/Forward/Answer frames. Connected and InitWritten are physical/local byte facts; no registration ACK exists. The caller owns all waiting futures; cancellation of a wait preserves cursors. Explicit reconnect has no callback/reply replay. Source loss retires every original token; duplicate active opaque IDs are rejected.

Callback rows, frame width, retained outbound bytes and syscall slices are finite.
When the callback table fills, input pauses while original replies and deadlines
continue. Original canonical deadlines are copied once. Native hard bounds,
partial-input and INIT bounds are checked before canonical-clock waiting.
Logical expiry removes wholly unwritten answers. Drop decisions wait for reply
capacity within their original bounded drain while unrelated replies progress.
A partially exposed obsolete answer closes its original MQ. Callback payloads
transfer to the caller in securely erased frames. The caller resolves each
callback or closes its source. Each callback occupies a row through its whole
reply write or source loss.

Original DNS service and its own privileged interception-helper runtime are external dependencies; connecting this API does not install redirection.
