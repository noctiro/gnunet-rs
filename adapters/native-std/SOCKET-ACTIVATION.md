# Windows socket activation

`socket_activation` transfers original unregistered stream listeners through
documented Winsock provider duplication. It neither rebinds endpoints nor changes
GNUnet service frames or network messages. The bounded anonymous section carries
process-local SDK records, not a service protocol.

## Ownership and startup order

1. Validate and quiesce overlapped AF_UNIX, IPv4 or IPv6 listeners. Exclude other
   I/O, socket-option changes, IOCP association and event-selection registration
   on every alias during transfer. Retain creator-owned filesystem cleanup leases.
2. Allocate `ExportSection` before process admission. Export only its read-only
   `AsHandle` through the native launch allowlist; retain no writable child alias.
3. Create the original child suspended. `publish` targets that original process
   object, writes one `WSAPROTOCOL_INFOW` per listener, seals the header and closes
   all parent writable access before the child is resumed.
4. The fresh child calls unsafe `Incoming::capture` before unrelated native,
   Rust or CRT owners. Capture checks the mapping extent, publication, ABI,
   target PID and inheritance, then exclusively owns the read-only handle/view.
5. Complete any managed console detachment before `materialize`: Winsock/provider
   initialization can create threads. Materialization reconstructs actual unique
   socket descriptors. Validate and make them nonblocking before reactor use.
   The parent retains source descriptors until actual import/readiness receipt.

The section admits at most 4096 listeners. Its version and native-record size
must match the receiving implementation. Source and receiver must use compatible
native providers and overlapped socket flags. Inherited local paths retain their
creator's cleanup authority; receiving listeners never acquire unlink ownership.

## Failure and cancellation

`Publication` confirms metadata publication only. It proves neither import nor
listener registration or service readiness. Source descriptors remain owned
through canceled waits and failed-child retirement. Higher layers await actual `.` from
the process-qualified startup channel.

`PublishFailure` retains the original error, successful export count, process pin
and mapping cleanup owner. Revoke start permission and explicitly terminate/drain
the same original child. Closing the section cannot cancel provider reservations
already installed for that PID. Failed resume also preserves original process and
thread owners; no destructor resumes, kills or waits for a child.

Capture/import failure, unused metadata or partial import requires fresh-process
exit. `discard` imports and closes every descriptor when successful. Tickets are
one-shot; do not retry or replay after partial failure. Socket owners close on
failure, and successful materialization explicitly retires its mapped view.

## Native references

The implementation follows Microsoft's
[socket sharing contract](https://learn.microsoft.com/en-us/windows/win32/winsock/shared-sockets-2),
[WSADuplicateSocketW](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaduplicatesocketw)
and [WSASocketW](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketw).
Provider rejection remains a native failure. Native fixtures must exercise
AF_UNIX and both IP families without substituting endpoints or skipping failure.
