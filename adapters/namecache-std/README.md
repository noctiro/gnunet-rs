# Bounded native NAMECACHE service

`server::Server` consumes the independently implemented official ciphertext cache
and the existing shared SERVICE access policy, Unix credential gate and process
RuntimeClock. The caller drives it inside its existing Tokio runtime. Construction
allocates finite owner metadata and a native timer; it creates no socket, Resolver,
thread, filesystem, disk worker, key loader or hidden task.

The external reference contract is the active v0.29.1 NAMECACHE API: cache,
lookup and delete operations with signed success/absence/failure results. The
plugin API abstracts the backend; the IPC has no per-operation fsync or restart
persistence field. The default C implementation happens to select SQLite, with
synchronous=NORMAL and WAL, or PostgreSQL. Those internal plugins are not a wire
requirement. This adapter explicitly implements volatile memory cache. A success is produced after memory storage/delete settles. No event or
report claims a SQL transaction, durable disk commit, fsync, publication or restart
recovery. Restarting this backend starts with an empty cache.

Each admitted source has its original shared `Framed<Origin>`, one retained RX
cursor and a bounded immutable FIFO TX queue. Its nonforgeable Client domain and
serial are paired with a non-reused write serial and the original RID. No queued result can be moved to another MQ or replayed on another connection. Unknown messages follow shared TOLERANT policy; malformed known requests,
credential failures, source allocation failures, EOF, source IO failures and
source hard deadlines affect only that physical source. A failure of the shared
clock is a process-port failure: sources close independently before its original
error is returned. The independent physical close path needs no clock or Resolver.

The production dispatch path reads the original frame and preflights its
reply size. It reserves queue metadata and allocates the final immutable frame
before invoking `Cache::handle`. No mutation runs while output credit is absent. A retained complete RX keeps its original finite input deadline while waiting;
partial original input and TX suffix cursors remain in the shared framing owner. The original Cache/Delete result is encoded only after the memory effect. An unexpected failure after that effect is terminal for the original source; it
cannot become a retry of the same mutation. Local queueing and whole-write events
are distinct from client processing. There is no synthetic cancel or extra ACK.

The cache derives query and expiry from the enclosed opaque block. The
outer CACHE expiry is ignored as in the reference service. It keeps the greatest
expiry under a query, reports delete presence/absence and returns at most
one exact stored block with that block's expiry. Public carried-key signature
checking is a client boundary; this opaque cache does not decrypt or use zone
secrets. The explicit maintenance uses the same process logical clock and strict
`expiry < now`. Its fixed logical target survives clock rollback. Native sleep
only wakes the owner; a source sample decides whether maintenance is due.

Per-source first-input, original-frame and oldest-output deadlines are finite
monotonic native limits. New bytes/frames and canceled waits do not renew them. Read/write preference, source scanning and listener acceptance rotate after actual
activity. One native turn performs bounded work and yields cooperatively. Slow
output retains credit instead of silently dropping results. Soft shutdown stops
admission, drains complete retained input and original output within the caller's
one grace bound, and closes incomplete/idle sources without inventing completion.

Cache bytes and query count have separate pure-core bounds. Native limits bound
sources, whole frames, TX frame/byte credits and syscall slices. TX accounting
retains the whole immutable body until its whole-write; logical wire
credits are not a promise about allocator metadata or exact RSS. No per-client
copy of the cache or worker-side shadow inventory exists.

The one focused model exercises the pure dispatch helper using only
preexisting public ciphertext/query fixtures. It checks original RIDs, reply
preallocation before effects, resource failure, inner expiry, exact lookup
body and delete outcomes. It passed after integration. One foreground/Unix profile observed
cache, exact lookup, deletion, miss, bad-source isolation and graceful shutdown
with the owned socket path removed. It uses only public ciphertext/query data. A separate public-cipher Unix profile passed in both official C/Rust directions,
including C API callbacks and a Rust memory-service restart miss. Neither
profile used private keys, devices, routes, external network or stopped host work.
