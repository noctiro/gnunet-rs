# Actual active TESTBED host utility

`System::create(&Instance,&mut[PortSlot],Options)` constructs a native owner for
exact current official TESTBED system/configuration functionality. Options are
explicit; `Options::from_environment` captures only GNUNET_TESTBED_PREFIX. A fresh
root defaults to a short /tmp name so generated Unix socket paths remain usable. An explicit prefix must be new/empty or this Rust utility's exact marked private
directory. It does not adopt a C GNUNET_HOME, read/import key fixtures, spawn a
peer/controller, or start any hidden thread/task/Resolver. Private-mode roots,
O_NOFOLLOW metadata, an File lock, namespace marker and a durable checked
path counter guard independent owned resources. Marker-qualified reopening is
not compatibility migration. Missing/corrupt existing counters fail closed.

`reserve_port` probes simultaneous TCP and UDP wildcard binds in both
selected supported IPv4/v6 families; IPv6 probes are v6-only. Probe FDs are closed
before return. Its opaque Reservation means logical per-system exclusion plus a
past bind observation, never future kernel exclusivity or peer ready. One TESTBED system should coordinate each caller's peers, as in the active C
contract. External processes may race to bind after the probe; no success masks
that fact. Release checks the exact original private token, not just port number.

`configuration_create` duplicates the existing loaded official CONFIG and leaves
its input unchanged. It actually commits its never-reused numeric path counter,
creates the private GNUNET_HOME and sets PATHS.DEFAULTCONFIG, ARM.CONFIG, PORT,
UNIXPATH, HOSTNAME, trusted IP/CIDR ACCEPT_FROM/ACCEPT_FROM6 and NAT.USE_LOCALADDR. Shared single_<service>_per_host keeps its existing port/socket. The active C's
num_<service>_per_host sharding branches are only FIXME/breaks; nonzero sharding
is explicitly Unsupported, not a fake implemented distribution. Actual per-config
port vectors reserve only the exact number needed, within limits; all reserved
ports are released on a refused generation, with separate cleanup reporting. Every generated Unix address is structurally checked by socket2 before return. No socket is bound merely by generating its name.

Rust fixes local configuration defects without inventing wire: inclusive low
range is honored (the C bucket scan skips it), key/ignore matching is safe and
case-insensitive, ignored final tokens need no trailing semicolon, advertised
port follows a newly assigned PORT unless explicitly ignored, IPv6 loopback ACL
uses ::1 and appends an explicit delimiter. These are configuration helper
semantics, not new controller messages. Shared CONFIG remains the only parser.

`write_configuration` serializes the shared CONFIG into zeroizing temporary
storage and does private staging/write/fsync, atomic rename or no-replace
link and parent fsync. Published is minted only after those original operations
succeed. Failure preserves Unchanged/Staged/Installed exposure, first actual
cause and independent cleanup cause/count; Installed followed by failure fences
new admission rather than replaying unknown writes. Default config and exported
files are separate publications. Filesystem fsync can block in the OS;
this synchronous no-scheduler utility has no fictitious finite disk deadline and
is not called from a network poll. Standard File/Socket Drop closes their owners;
it provides no extra kernel close-errno or remote-revocation receipt.

`release_configuration` releases original logical port tokens only; it does not
stop any external process or delete a config. `destroy(remove_paths)` stops core
admission and explicitly keeps or actually removes only this marked original
root, checking its original inode/marker and syncing parent. Other exported
paths remain. First operation and independent cleanup failures remain distinct. The caller decides that removing an owned tree is appropriate; no process/remote
quiescence is inferred. Drop alone does not claim directory removal.

No compiler/Cargo/model, crypto/key/entropy, filesystem/store, native bind,
network/helper/process or C execution occurred. Central compilation and actual
public config/port behavior qualification remain outstanding. Full GNUnet peer,
ARM, transport/topology capabilities remain separate subsystem obligations.
