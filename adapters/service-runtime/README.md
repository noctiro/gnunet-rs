# Shared GNUnet service runtime

This package extracts the existing STATISTICS application's listener startup
into a Unix std host package. It adds no production wire protocol and does not
claim a complete GNUnet generic service implementation. The behavior profile is
GNUnet v0.29.1, revision `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.

The public API is `Activation`, `ActivatedSocket`, unsafe `capture()`, safe
`bind_private()`, `CreatedPath`, `private_parents()`,
`BoundListeners::bind(&config, section, activation).await`, borrowed
`listeners()`, `unix_paths()`, `failures()`, and
`service_options(&config, section, shutdown)`.

Call `capture()` once as the first host initialization under its full documented
single-threaded, exclusive foreign descriptor contract, before opening runtime,
configuration or logging files. Validation finishes before ownership transfer. Later OS adoption errors are fatal startup failures. All descriptors use the
launcher's numeric `LISTEN_FDNAMES`, including arbitrary nonconsecutive numbers;
there is no fd3 assumption, systemd descriptive-name interpretation or LISTEN_PID
check. Stdio listeners move to fresh descriptors before their old slots receive
`/dev/null`. Capture marks listeners nonblocking/CLOEXEC and removes only
LISTEN_FDS. Drop closes only the owned listener descriptors and leaves inherited
Unix paths to their creator. One-shot protection also covers empty/error results.

After capture, create a current-thread runtime and bind the explicitly selected
service section. Nonempty activation bypasses all configured addresses; it does
not suppress the host's separate ACL/TOLERANT setup. Fresh binds read UNIXPATH,
PORT, BINDTO and DISABLEV6 solely from that section. BINDTO uses synchronous native
resolution, with no Tokio worker spawned across private Unix creation. Tests use
numeric loopback addresses so they perform no DNS lookups. Without BINDTO, the
existing wildcard v6/v4 behavior remains; callers select their own config. At most 64 resolved addresses are admitted, with an explicit capacity failure. A missing/zero PORT permits a Unix-only service. No configured listener and no
nonzero port is an error; if every endpoint fails, bind fails. If another succeeds,
`failures()` preserves alternate endpoint errors for the host to report.

Fresh TCP sockets use SO_REUSEADDR, IPV6_V6ONLY for v6, nonblocking mode and the
original backlog 5. `service_options` parses all four existing address ACL lists
and TOLERANT from the same explicit section and retains the caller's shutdown
mode. The host must pass those options to its accepting/dispatch driver;
obtaining an options value does not enforce admission by itself. This extraction
depends only on generic config/types/crypto/native packages, avoiding any
domain client or facade cycle. `Listener` borrowing prevents references from escaping `BoundListeners`.

Private Unix creation is the bind under temporary umask077, not bind then
chmod. A synchronous RAII guard restores the exact previous umask on success,
error and unwinding; its private mutex serializes this package's own binds. The host must exclude unrelated process-wide umask users and file creators during
this startup section. Missing parents request mode0700; existing directories keep
their permissions and follow ordinary OS path resolution. The stale-path probe
only considers socket inodes; live sockets, files and symlinks are never
unlinked. A refused/not-found connect may remove the observed stale socket after
an inode check. The asynchronous connect probe has a five-second bound. This is
an intentional bounded host policy around C's blocking precheck.

The listener set declares its socket vector before its CreatedPath guards, so all
listeners close before path cleanup. Guards remove only an absent-or-matching
(device,inode) path and leave already-observed replacements alone. Metadata and
unlink remain separate OS calls: this is not an atomic protection against hostile
concurrent path replacement or later inode reuse. Callers must control their
service directories and creation/removal lifetime. `CreatedPath::capture` is for
new paths the caller owns; it must not register inherited or foreign paths.

`src/lib/util/service.c:get_server_addresses/setup_service/open_listen_socket`,
`network.c:GNUNET_NETWORK_socket_bind/GNUNET_NETWORK_unix_precheck`, and the
launcher's `os_process.c` are the official source basis. The extraction preserves
the original audited native function bodies exactly and records their hashes in
the generated extraction receipt. The original native operations are the existing fd
capture/flags/relocation, bounded macOS libproc or SO_ACCEPTCONN query, early-main
environment removal, and paired umask guard. Safe modules forbid unsafe code. The separate `readiness` module adds one scoped native Tokio registration with
an explicit stable descriptor ownership contract; no global unsafe lint exemption
is introduced. The
macOS ABI fixture checks the SDK option offset and buffer size independently.

Original C malformed-activation prefix acceptance, duplicate ownership and weak
socket boxing are rejected before Rust ownership. Arithmetic overflow is checked. Inherited blocking Python fixtures are normalized; the C service comparison uses
nonblocking descriptors as its official launcher does. Rust reports configured
invalid PORT or ACL failures explicitly; C can log and continue as zero PORT or
drop a malformed ACL. The existing safe std native address resolution and enabled
family filtering are retained, rather than reproducing every internal getaddrinfo
hint/diagnostic priority or C's separate IPv6 capability probe. These are explicit
profile boundaries, not evidence that all service.c behavior is implemented.

USERNAME/user switching, daemonization, CLOSE_LSOCKS readiness signaling,
UNIX_MATCH_UID/GID checks of peer credentials and registration with the scheduler,
plugin loading and the remaining public generic service/util APIs stay pending. Signal handling, persistence, application control files and protocol state remain
with each service. No system account, host environment, /etc or system DNS setting
is changed by these tools. Child environment dictionaries are process-local.

The repository manifest and standalone Cargo.toml.in template are both bound by
the verifier; generated Cargo.lock stays in its output directory. The verifier generates an independent crate, lock and target
under a fresh external output directory, pins cargo1.99.1, resolves only cached
versions already pinned by the repository lock, and runs all later commands
locked/offline. It compares workspace and generated package metadata
for identical direct dependency versions, defaults, features and target/path
requirements before testing the generated crate. It then executes the subprocess fixture through both statistics and
resolver sections and the hash-checked unchanged normal C STATISTICS daemon. The one-byte fixture echoes observe socket ownership only; official GET/END IPC
is used for the C daemon and no echo protocol enters production.

```sh
python3 /path/to/candidate/tools/verify.py \
  --repository /path/to/gnunet-rs \
  --upstream /path/to/unchanged/gnunet-v0.29.1 \
  --reference /path/to/normal-C-build-result.json \
  --output /path/to/new/external-proof
```

The duplicated application modules were removed during integration. The extraction
checker compares the shared functions with the reviewed migration hashes in
`tools/migration-baseline.json`; that record preserves the original review without
compiling a second implementation. Functional acceptance separately runs actual
shared-runtime tests and normal C subprocess comparisons.

`PrivateListener`, `bind_private_with_backlog` and
`bind_private_with_permissions` let ARM use its exact first listen backlog5 and
chmod-before-listen order. They reuse the same serialized private umask guard;
safe socket2 owns the new socket and `CreatedPath` owns only its new pathname. An failed first listen closes the socket before removing that inode. The optional chmod and reuse-address failures remain explicit warnings.

`readiness::RegisteredReadiness` exclusively owns an unchanged `OwnedFd` for the
entire reactor registration. There is no mutable-inner or replacement API. `into_owned` deregisters first. The poll operation confirms a cached readable
hint with nonconsuming nix poll0, clearing false WouldBlock hints, and separates
IN, HUP, ERR and invalid-descriptor errors. It never accepts, reads or invents
an application response. Canceled waits leave the registration and FD owned by
the caller. The ARM listener host uses this shared owner for one-shot leases.

The shared `process` module owns native command/descriptor preparation, original
child/control capabilities and consuming waits. Its narrow native implementation
is `src/native_spawn.rs`; ARM's launcher delegates to it. See [PROCESS.md](PROCESS.md)
for admission versus exec/readiness, source signal/stdio differences and remaining
utility obligations. `pipe()` returns unique nonblocking/CLOEXEC ends above stdio. The sole helper is still published by `gnunet-arm-host`; standalone runtime tests
freshly build that thin helper in their own target before executing native unit
boundaries. Whole-workspace tests build it through the ARM integration targets. This test packaging does not add an ARM dependency to the production runtime.

Connection and accepted-stream ownership is shared here. `connection::Connection`
owns exactly one Unix/TCP stream and an optional `ConnectionLease` dropped before
the stream. Attaching another lease rejects and returns both owners unchanged. `Listener` accepts original runtime connections directly, with optional native
reactor initialization and ordered diagnostics before domain admission. The
reactor policy has no select/FD_SETSIZE descriptor ceiling; OS failures
remain observable. The explicitly historical native source initializer retains
its separate C parity scope. CLIENT Endpoint/Resolver effects live in
`gnunet-client-host`; business ACK/state owners stay in adapters.

`framing::Framed<Origin>` owns one original Connection, private persistent RX/TX
cursors and immutable `OwnedFrame` bodies. A waiting future borrows that owner:
canceling the wait cannot replace its socket, bytes, cursor or opaque origin. Only zero-written frames can be removed; started tails must drain or retire their
whole MQ. `reserve` preflights queue metadata, and domains allocate the final body
before irreversible work. `enqueue_owned` freezes/moves that allocation without
copying it. Rejection returns the original secure bytes and origin unchanged. Whole-frame and remaining-wire accounting are explicit domain choices, with
separate additional control budgets. Logical budgets are not exact RSS caps;
retained Vec capacities, one written prefix in Remaining mode, RX storage and
metadata are additional storage costs. Domains retain deadline/fairness/resource
policy; framing does not sample another clock, grant credit or consume a nonce.

Each tagged positive native write returns its exact original origin/count once. The embedding owner must report that progress before processing subsequent RX. Only `Framed<()>` exposes untracked batching: up to64 stack IoSlices, still limited
by the original IO-byte quantum, with one native write per successful
poll. Its aggregate byte/frame count supplies no synthetic operation identity. Ready RX storage stays until explicit `release_frame`; `frame_mut` permits secret
consumers to wipe precisely that complete frame. Reads never overread the next
header. Release wipes only current storage and supplies no ACK or processing
success. Premature release cannot discard a partial frame. Fatal read/write errors
require retiring/dropping that physical owner before a new epoch; partial secrets
remain until then. Canceling a wait and Interrupted preserve the cursor instead. Owned TX bodies use Zeroizing<Vec<u8>>; release/retire/drop erase retained RX and
all removed or retired TX bodies. No payload Debug or mutable admitted-body API
is exposed. Lease-before-socket drop and original native error identity remain
unchanged. CORE and TRANSPORT use this mechanism; TCP/Resolver migrations remain
separate because their scheduling/callback semantics differ.

`RegisteredIo` preserves one IO attempt per poll, including caller-defined
`FnOnce` operations. If a cached ready hint is followed by WouldBlock,
Tokio clears that hint but may not have registered this poll's waker. All four
read/write entry points schedule one cooperative caller turn before returning
Pending. That turn rechecks the caller's original guards and registers empty
readiness, or attempts one newly ready operation. There is no internal syscall
retry, replacement descriptor, changed byte cursor or relaxed deadline. This
also applies when an idle terminal has no unrelated socket event to wake it.
