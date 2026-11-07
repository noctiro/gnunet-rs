# Official DNS interception client

This is DNS service IPC, not the DNSSTUB external UDP resolver. It sends INIT flags, retains opaque eight-byte callbacks from one MQ, and sends only official Drop/Forward/Answer frames. Connected and InitWritten are physical/local byte facts; no registration ACK exists. The caller owns all waiting futures; cancellation of a wait preserves cursors. Explicit reconnect has no callback/reply replay. Source loss retires every original token; duplicate active opaque IDs are rejected.

Callback rows, frame width, retained outbound bytes and syscall slices are finite. Original canonical deadlines are copied once; native hard bounds, partial-input and INIT bounds are independent and checked/alarmed before canonical-clock waiting. Logical expiry replaces wholly unwritten answers by a Drop; a partially exposed obsolete answer closes only its original MQ. No other request can inherit it. Callback payload is one securely erased OwnedFrame, transferred to the caller; dropping it is not a wire continuation. The caller must retain/resolve it or close the original source. All callbacks count against the fixed live-row ceiling until reply whole-write/source loss. No hidden task/Resolver/service exists.

Original DNS service and its own privileged interception-helper runtime are external dependencies; connecting this API does not install redirection.
