# Persistent FreeBSD TUN recovery

## Record and native identity

`OwnedTun::open_freebsd_recoverable(name, checkpoint, limits)` combines a private
checkpoint with exclusive native provisioning. It retires the saved native owner
before admitting a new allocation, commits allocation intent before creation,
and commits the complete identity before returning packet ownership.
`Device::open_freebsd_recoverable` exposes the same lifecycle to VPN coordinators.

Persistent interfaces and recoverable transient interfaces carry a versioned
`gnunet-rs-tun:1:` description containing the complete canonical selector as
hexadecimal bytes, including a random 256-bit correlation nonce. The managed
constructor installs/read-checks it before opening the data FD, configuring
framing, renaming or selecting FIB. It needs 273 description bytes including NUL.
`recovery_record()` exposes the checkpoint selector on `OwnedTun`, `DeviceHandle`
or retained `InterfaceCleanupError`. Untracked transient and externally owned
interfaces have no selector. The description is reserved while owned; changing
its identity fields fences cleanup.

`recovery::Record` encodes a canonical 128-byte `GNTUNR01` private record containing
the actual interface name/index, original canonical devfs unit, complete Unix
device-file identity and correlation marker. Decoding validates names, platform
tags, nonzero index/marker and reserved bytes. It performs no native operation
and grants no administrative ownership. The marker is correlation data, not a
secret or an immutable kernel birth ID.

## Reacquisition and cleanup

On FreeBSD, consuming `Record::recover` resolves the original interface index
and checks the complete marker identity. A renamed interface can be located
without treating a newly reused old name as its owner. Absence of that index
returns `Observation::Absent` with the unchanged selector; this is a current-scope
observation rather than a destroy acknowledgement. Name changes do not change
the index, nonce, canonical device unit or saved file identity required by the
marker check.

Recovery inspects the canonical devfs character node and checks the opened
original device identity, L3 TUN type, actual name/index and full marker. Cleanup
can qualify an unconfigured L3 TUN whose framing flag is still zero. Packet
publication remains separately gated on verified `TUN_IFHEAD`; recovery never
resumes incomplete packet configuration or changes its framing. Canonical device
selection comes from the full marker, never a guessed rename alias.

Only successful physical qualification produces `Observation::Ready(Cleanup)`.
Its explicit `close` closes that reacquired descriptor once. Manual interfaces
then use native destruction; tracked transient interfaces require observed
kernel removal and return a retained WouldBlock error while other users remain. The original interface owner rechecks its index and
marker before destruction. Independent close/destruction failures remain in
`DeviceCleanupError`; destruction can wait for other open device users.

A failed qualification retains the selector, original error and any descriptor
already opened. `Failure::take_opened` transfers that descriptor for explicit
close without administrative interface cleanup. Close it before retrying.
Dropping any owner closes its descriptors without certifying interface cleanup.

## Durability and administrative scope

The recoverable constructor requires an existing private parent directory. Its
checkpoint holds a native exclusive lock on the original single-link private
file, plus original-directory/name fences. Two 256-byte `GNTUNJ01` frames bound
storage to 512 bytes. Sequence numbers, canonical zero padding and SHA-256 detect
damaged frames; the hash does not authenticate hostile writers. An invalid
nonzero frame cannot roll state back to Empty. A write/sync uncertainty fences
further mutation until the same file is reconciled.

States are Empty, Creating(intent) and Active(record). For a pending intent,
startup performs a read-only name/index inventory, including interfaces without
IP addresses, and reads each native description. Discovery retains at most 4096
names and requires one matching nonce with a consistent index. Inventory limits,
read errors and duplicate matches abort discovery; a partial scan cannot select
a winner. Its result is metadata only, committed to Active before the original
physical device is reacquired for cleanup.

A crash after allocation but before marker installation remains unresolved.
No matching marker does not prove that creation had no effect. Such an intent
still fences recreation and requires operator inspection of the original scope.
Stop every checkpoint owner before replacing an unresolved intent after
out-of-band cleanup. The kernel offers no atomic create-and-marker transaction.

Explicit close retains native retirement separately from checkpoint retirement.
If native destruction/removal succeeds but checkpoint clearing fails, the
retained error can reconcile the original checkpoint and retry its metadata
retirement without another native destroy or descriptor close. Drop releases
descriptors/locks and leaves durable recovery debt; the next recoverable startup
reacquires it before allocation. Startup keeps the same original checkpoint
lock through native retirement and the next intent; errors retain the lock with
the original native retirement owner when metadata cleanup is incomplete. Independent duplicated descriptors remain
caller-owned, and manual native destruction can wait for those users.

The lower-level `open_freebsd_exclusive` still leaves private record publication
to its caller. Encoding or borrowing a selector is not a checkpoint. Creating intents with a complete native marker can be resolved without a
previous on-disk selector; unmarked intents remain fenced. Native qualification and remaining consumers
are tracked in [implementation status](../../IMPLEMENTATION_STATUS.md).

Recovery requires the same intended jail/VNET and devfs administrative scope.
The caller must serialize interface/device administration throughout creation,
reacquisition and destruction. FreeBSD has no atomic compare-and-destroy ioctl;
name/index/marker checks cannot fence a concurrent privileged administrator.
Only privately retained records from the original owner may drive recovery.
Opening a TUN has native side effects, including close-time address/route cleanup
when later qualification fails, so recovery is not a read-only probe for
untrusted selectors. Transient lifetime follows the kernel's final-FD-close rule.

## Native references

- [Interface description and buffer handling](https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/sys/net/if.c)
- [Description ioctl definitions](https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/sys/sys/sockio.h)
- [TUN close and transient lifetime](https://raw.githubusercontent.com/freebsd/freebsd-src/releng/15.1/sys/net/if_tuntap.c)
- [Native header ABI probe](tests/freebsd_tun_recovery_abi.c)
