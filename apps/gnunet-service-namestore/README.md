# gnunet-service-namestore

Standard SERVICE entry for the existing official NAMESTORE IPC Server and its
independent marked Rust snapshot store. The shared SERVICE options are
`-c/-d/-h/-L/-l/-v`; `-v` retains its version meaning. `-d` performs the actual
shared daemon split and original parent readiness handshake. No PROGRAM task
scheduler, private daemon or compatibility flag layer is added.

The selected Logger/Reporter handles service diagnostics, including
parent declaration, process identity, listener alternatives, source failures,
storage/cleanup observations and terminal errors. Once selected, terminal
failures do not unconditionally bypass `-L/-l` through a second fd2 write. The shared SERVICE configuration loader preserves XDG/user-then-installed
selection instead of PROGRAM's default filename search.

The original inherited descriptors are captured once before initialization. Actual daemon split occurs before runtime, account lookup, sockets, store or
worker. The parent closes its descriptor copies and waits for the original
status; the child refreshes the selected Logger's PID. On one current
thread runtime, TCP/activation listeners prepare before configured USERNAME;
new Unix listeners finish afterward with the original UID/GID match flags. Inherited sockets and existing filesystem parents retain their ownership.

Only after all listeners finish does the existing Rust-only storage
path open, recover and start its sole worker. A new namespace synchronously
commits its genuine empty canonical image under the same original lease before
worker startup or READY. No await/cancellation boundary splits that first local
transaction. An existing marked namespace with no canonical image, or a committed
empty body without the normal format header, is refused rather than reset. Commit failures keep their storage cause and certainty. `[namestore-rust] DIRECTORY`
remains an absolute fresh or marked private Rust root; existing C database
files are neither read nor imported automatically. The configured snapshot body capacity must fit the 12-byte empty format before
any store is opened. Original inventory, frame, stream, record, memory and
operation-time settings otherwise remain unchanged.

The same SharedClock reaches Reporter, the explicit Resolver and original
Server ports. READY follows recovery, worker start and successful Server
construction, then an installed Stop check, stdout write/flush and the original
once-only ChildReady. It does not claim remote operation, client processing,
durable completion of future requests or any extra external Connected gate.

SIGINT/SIGTERM, parent control, selected logging failure, Resolver or service
failure retain the same original owners. Soft stop captures one native target
checked before canonical/native classes; a ready class cannot reset it. A
permanent Reporter failure stops new Resolver IO and normal business, entering
the original finally path directly without polling another normal class. Each
class rechecks the original native target. Source close is followed by the one original
Server.shutdown future while the same healthy Resolver is fairly driven.

A started worker is not dropped silently when Server construction fails: after
its original borrow ends, its shutdown/join is awaited. The same fallback
runs if no worker report was supplied by Server shutdown. No timer,
boolean, dropped future or metadata substitutes for a worker result. OS filesystem work can block and is not claimed to be force-preemptible.

Terminal errors retain the typed Server shutdown, original worker result,
independent worker/Resolver-drive/Resolver-close/output/logging causes, and
bounded first diagnostic facts. A sole Logger failure also retains the real
shutdown report. Existing native bytes, stream credit, storage job/receipt,
unknown exposure and durable state semantics are unchanged.

No core/crypto/host algorithm or stopped family was changed.
