# Windows socket activation

`socket_activation` transfers original unregistered stream listeners through
documented Winsock provider duplication. It neither rebinds endpoints nor changes
GNUnet service frames or network messages. The bounded section carries
process-local SDK records.

## Ownership and startup order

1. Before process admission, the transfer qualifies the exact batch of original
   TCP and AF_UNIX listeners and refuses repeated descriptors. The caller excludes
   I/O, socket-option changes, IOCP association and event-selection registration
   on every alias during transfer. Retain creator-owned filesystem cleanup leases.
2. Reserve one unnamed section for that batch. The inherited route exports
   only the read-only handle through the native launch allowlist. A cross-session
   launch supplies its one-time verification key in the original environment.
3. Create the original child suspended. Launch binds the section to that
   process object and prevents admission of another child through it. `publish`
   accepts only its bound suspended owner, writes one `WSAPROTOCOL_INFOW` and
   access indicator per listener, seals the header and closes all parent writable
   access. For a session crossing, duplicate the resulting read-only handle
   into the original child before granting resume permission.
4. The fresh child captures the inherited handle or receives the signed grant
   on the bootstrap pipe. The supervisor sends the grant to the qualified
   original child. The child authenticates the grant with its launch key before
   interpreting its target-local handle. Capture checks the publication, ABI,
   mapping extent and target PID, then owns the read-only handle and view.
5. Complete any managed console detachment before `materialize`: Winsock/provider
   initialization can create threads. Materialization reconstructs actual unique
   socket descriptors. Validate and make them nonblocking before reactor use.
   The parent retains source descriptors until actual import/readiness receipt.

The section admits at most 4096 listeners. Its version and native-record size
must match the receiving implementation. Source and receiver must use compatible
native providers and overlapped socket flags. Inherited local paths retain their
creator's cleanup authority; receiving listeners never acquire unlink ownership.

`AccountExportSection` qualifies native TCP listeners and named AF_UNIX
listeners with original pre-listen protection for the selected account. Launches
in the supervisor's session inherit the read-only handle. When the transfer
includes local protection, the original launch declares the supervisor SID and
the child checks it against the kernel owner of the inherited mapping. Cross-session
transfers use a noninheritable duplicate with read and security-query access.
The child checks the section's kernel owner against the signed publisher SID.
The target PID is checked before any record is imported.

For either route, the child process DACL permits the supervisor's provider
to duplicate into that exact target. The cross-session transfer uses the
process handle returned by native creation. An undelivered grant leaves the
duplicate owned by the original child's handle table until its actual exit.
[Windows object duplication](https://learn.microsoft.com/en-us/windows/win32/sync/object-duplication)

## Local endpoint access

`local_path::ListenerBinding` creates the original named AF_UNIX socket,
installs its node protection, then starts listening. `ProtectedListener` owns
that socket, the original path cleanup and its ACL evidence. A trusted launcher
can borrow it as a `Source` for activation. The protection records the selected
primary-token user and, for group access, its exact primary group. In account
mode, the supervisor keeps the node's owner and maintenance rights. The selected
user and whichever other principals the mode allows receive connect access.

The launcher retains the original node handle and checks the socket descriptor,
native bound name and full file identity. When a supervisor needs its own copy of
a source socket, `Source::try_clone_to_owned` performs those checks before
duplication and binds the same node identity and access policy to the new
descriptor. Account transfers qualify the supervisor's SID against the kernel
owner of the section. Ordinary inherited sections must have the same owner as
the receiving primary token to carry
local protection. The child checks the installed user and group claims against
its own primary token before native import. The imported name must identify the
same original file object. TCP and bare external descriptors carry no local
evidence. The original installed policy is required because clients may
already be in the accept queue at handoff.

## Failure and cancellation

`Publication` confirms metadata publication only. It proves neither import nor
listener registration or service readiness. Source descriptors remain owned
through canceled waits and failed-child retirement. Higher layers await the
readiness receipt from the process-qualified startup channel.

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
