# Standard Rust PILS SERVICE

Run `gnunet-service-pils -c official.conf`. This executable runs the independent
Rust PILS service and uses no C daemon, C private-key importer or libgnunet FFI. The active official v0.29.1 source reads `[PEER] PRIVATE_KEY`: an exact raw32
initial seed, created once from native entropy when absent. The similarly named
`[PILS] SECRET_KEY_FILE` in the source's configuration template is unused by its
active service. The Rust foreground follows the active source.

The standard executable uses the shared SERVICE option table
`-c/-d/-h/-L/-l/-v` (`-v` is version). It captures the original activation and
parent-control descriptors first and selects its Logger before any runtime,
account lookup, listener path guard or private-root I/O. `-L` controls actual
socket/service diagnostics and `-l` retains the selected owned file; the Logger
already keeps private file ownership above the standard FD slots.

`-d` consumes the shared explicit fresh-process split. Only the child continues
with configuration and authority initialization; setsid and stdin/stdout
`/dev/null` redirection retain original activation/control/stderr/log owners. Child log PID metadata is refreshed without reopening the selected file. Parent
drops its copies of activation/control and waits on the original ready pipe,
never for the live daemon to exit. Only the child-ready byte means success;
EOF, early stop, failed/drop initialization or failed status write cannot mean
ready. The generic async embedding does not detach or change process identity.

The existing configuration loader applies installation/user defaults and the
selected SharedClock receives configured testing skew. That same clock authority
feeds Logger and PILS Host; no independent SystemClock is substituted. PILS USERNAME resolves under the startup identity. A sole current-thread runtime
is entered only to adopt activation or prebind TCP while privileged. After the
explicit UID/GID/initgroups transition, `ListenerPreparation::finish` creates new
Unix paths under the selected account, without chowning any existing inode or
reopening original descriptors. Only then does the existing actual
`startup::prepare` read/create/fence/synchronize the original private-root owner,
outside polling and before service tasks. An idle current-thread runtime and
prebound listeners may exist across this synchronous boundary.

Unix UID/GID flags still use shared kernel credentials with UID priority; TCP
retains configured ACL and common initialization/EMFILE semantics. No caller
receives a synthetic privilege, root, signature, publication or ready proof.

Private-root preparation loads/creates, locks, synchronizes and verifies the key
before service polling. The foreground prints `READY <public-peer-hex>`
only after that preparation and listener binding, then flushes stdout and
consumes the original once-only ChildReady writer. A merely bound socket is not
ready; the prepared Host must still retain its derived public authority. All key files and persistent lock files require the effective owner, one hard link and no
permissions for other accounts. The parent directory must be owned by
that account and not writable by others. New parents use mode0700. Existing
malformed, symlinked, replaced or insecure files fail instead of changing the
identity. A post-rename durability failure publishes no service; next startup
synchronizes and rereads the same committed raw32 before returning an identity. The lock fences cooperating Rust writers in an owned namespace, not concurrent
hostile replacement or an unrelated C writer. Socket polling performs no disk
synchronization or detached private-root job.

Each accepted connection immediately receives the signed1831 HELLO and is
subscribed. FEED1834 uses its addresses and has no ACK; the service generates a
new signed HELLO and broadcasts it to every original live MQ in FIFO order. Normal v0.29.1 address hashing does not cover addresses, so normal FEEDs refresh
the HELLO without changing the derived public key. The explicit conditional
profile remains available through the pure owner. The active C service has no
periodic HELLO/identity refresh task, so this foreground does not invent one. The SIGN1832/1833, DHKEM1835/1836 and legacy DH1837/1838 handlers preserve
original connection-local request numbers and use the current key.

One caller task drives the bounded host. Default bounds admit64 streams, keep
one65535-byte RX buffer per admitted stream, and bound each immutable TX FIFO by
8 frames/262140 retained wire bytes. Public address scratch is65535 bytes and
address count4096; these are local capacity policies. Work rotates among input,
output and listeners with a retained cooperative yield after each bounded
action. Slow clients can be physically closed with their original local
queue error. Partial replies drain only on their original MQ or are erased when
it is closed. Signing/DH/KEM output is erased by the shared framing owner. Native writes are local transfer facts and grant no remote processing ACK.

SIGINT/SIGTERM, including original parent-control bytes, close all actual
streams before erasing the active/master key owners and releasing their writer
lease. Original per-stream failures remain visible without stopping unrelated
clients. The final `STOPPED` report contains public counters only.

The narrow native model covers both Unix and TCP, four handlers, signature
and DH/KEM verification, immutable FIFO broadcast and reopening a fresh test's
durable root. It does not read any existing C private file, run a C
counterpart or establish whole-node interoperability. Historical client/C
receipts retain their original source and scope. Existing pure behavior rejects
malformed FEEDs atomically and validates exact nonempty purpose regions; it does
not reproduce the reference's malformed-feed reset or unsafe sign-size checker.

## Startup

`startup::foreground_listening` consumes prepared listeners and the same
private-authority Prepared owner; the original `foreground` embedding binds and
uses the same internal driver. Neither embedding API changes identity. Original
private-root/provider/crypto algorithms, request IDs, erased framing and native
reply ordering are unchanged. Ready-callback failure also reaches Host
close/event cleanup; independent service and cleanup observer errors are both
retained. Selected-log IO failure wakes ordinary shutdown, and its original error
is combined only after all streams close, keys erase and writer lease
release. No cancelled output is reported as fully written.
