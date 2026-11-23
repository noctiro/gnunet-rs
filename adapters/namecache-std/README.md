# Bounded native NAMECACHE service

The host serves official NAMECACHE cache, lookup and delete requests using
shared SERVICE listeners, native peer credentials and the process clock.

## Cache and persistence

`Server::new` selects a memory cache. `Server::new_persistent` acquires the sole
writer lease for a private directory and restores structurally valid, unexpired
query records before the caller signals readiness. The file backend stores one
opaque encrypted block per query, synchronizes each replacement file before
atomic publication and synchronizes directory changes where the platform supports
that barrier. Windows supports normal restart recovery with native file flush and
rename operations.

Both backends derive query and expiration from the enclosed block and retain the
greatest-expiring version. Lookups return the exact stored block and its expiry.
Consumers check the carried-key signature. Maintenance applies the strict
`expiry < now` predicate using the process clock and removes files in bounded
batches. Its logical clock target survives a clock rollback.

## Interfaces and request lifetime

`server::Ports` supplies SERVICE options, native access policy and a shared
clock. `server::Limits` bounds admitted sources, framing, TX credits, syscall
slices and source deadlines. The [normal service](../../apps/gnunet-service-namecache/README.md)
maps its configuration onto the shared server across all supported platforms.

The host reserves reply credit before dispatch. It keeps the original input
deadline while waiting for output credit or a file operation. The Tokio blocking
pool runs one file operation at a time. The host continues native socket I/O
while preventing other requests from observing an uncommitted change. If storage
returns an error the host closes the sources and returns the error. A committed
reply belongs to its original connection and request ID, even if that connection
closes before delivery.

The caller drives the server and closes the original sockets on shutdown.
`finish_storage` collects the outcome of any final file operation. Soft
shutdown drains complete input and queued output within the caller's grace.
Cache memory, source queues and the pending file operation have separate bounds.
