# Conversation native service host

`gnunet-conversation-host` connects the official Conversation IPC to the existing
bounded Conversation core, PILS identity client and CADET client. Each accepted IPC Line owns one explicitly polled pinned local future, its own
original identity/CADET sources and multiple branded calls. It starts no hidden
task or media helper. `Server::ready()` denotes IPC admission, not an established
peer channel or remote acceptance; normal SERVICE owns the listeners.

The Line's Awaiting, Active and Failed phases exclusively own initialization and
session authority. Active holds the original core and verified PILS observation;
its current domain identity comes from that core. Healthy peer updates preserve
the core, logical port, calls and admitted effects; each incoming call keeps its
original signature target. A changed MQ or regressing observation refuses
replacement, and failed construction cannot publish identity or retry with
another instance. Identity events have a bounded queue-slot preflight.

`Sources::new` snapshots both selected endpoints together, freezes those
endpoints, and requires the identical shared Clock. A Line first obtains the
PILS peer and original source generation. The current peer, generation,
signed HELLO lifetime, cancellation and original native/canonical targets guard
operations, including guarded CLIENT connect/Resolver steps. A clock
sample rechecks already observed state and never claims a newly observed PILS
loss. Source loss retires the original sources rather than replaying a Line on
a replacement MQ. The first original typed cause, pre-attachment retry
errors and independent cleanup cause remain available in `LineReport`.

`RegistrationAccepted` reports that one complete original731 was accepted by
the local protocol core and its input frame consumed. It exposes only the
original IPC Line serial, with a bounded event-slot preflight before core
mutation. It is not a CADET port-write receipt, a protocol ACK or remote-ready
notification; wire bytes and processing semantics are unchanged.

Every Open/PeerFrame/ClientFrame/ReceiveDone is tied to the original core effect
and native Port, Channel, Transmit or Delivery. Whole local MQ writes
are Written; they do not establish a remote ACK or a picked-up call. A complete
outer peer DATA packet is shape/direction validated before its first inner
message reaches the core. The original Delivery, source and offsets remain
owned. Nonfinal inners use ReceiveDone-only Processed; the last inner receives
Written only after the original credit ACK is completely written. Unknown
or malformed tails receive no fabricated credit. Private 734 ego bytes enter
only the zeroizing core and secure IPC framing, without Debug or log output.

While a Packet is held, the same guarded CADET driver polls only existing
output. It accepts no later buffered event or native input until all original
inners and the final receive-credit write have finished. This preserves a
complete received payload across a later channel-destroy event without copying
or deferring that terminal event. The original input/output/native deadlines
and source failures still apply. `ChannelDestroyed` records the SDK
event and original Line/call/CID/channel/MQ epoch before the later `CallClosed`;
its `mq_current` field only reports the already observed source generation. Each event has a bounded queue-slot preflight before its mutation. Channel
destruction never fabricates a peer HangUp, an outgoing ring write, or a healthy
call result; EOF and MQ loss keep their original failure paths.

A frozen bounded effect scan preserves each channel's send/input-credit FIFO
and the Line's IPC FIFO while allowing other calls to progress around a slow
peer. Native pending operations retain their original target and exposure. Cancellation of unsafe partially exposed immutable DATA physically retires the
original MQ/Line. Known whole writes stay Written during later retirement;
unknown or partial operations retain their original Lost/Unsent outcome. Per-call invalid input is rejected through its native channel when safe. EOF/source close does not manufacture peer Pickup or successful wire HangUp. Clock-free shutdown attempts every original Line and records undrained debts;
undrained cleanup is fatal to new admission.

Default native profile: 32 Lines, 256 global calls, 8 MiB reservation per Line,
256 MiB aggregate reservation, IPC/core frame extent 65535, syscall slice 65535,
eight finite work units, startup/first-input 30 seconds and incomplete-input or
held peer input 15 seconds. Core defaults retain 32 calls, 128 effects, 1 MiB
queued payload and 2 MiB core retained storage per Line. Configure limits
explicitly through the public validated `Limits`. Actual tables, owned packet
capacities, fixed selected endpoint storage and framing are included with a
conservative native-owner envelope. This is a retained-owner admission budget,
not a measured allocator or process RSS/peak-memory guarantee. External Clock,
Resolver and runtime provider internals remain their owners' responsibility.

Peer sends retain the actual 64348-byte CADET payload bound. A maximum peer
AUDIO745 converted to IPC AUDIO739 adds its original four-byte CID, yielding
64352 bytes; consequently the native core defaults to 65535 and IPC must cover
the selected core limit. The pure core and official wire format are unchanged. An incomplete frame keeps its original partial deadline, including the read
that finishes it. A complete frame waiting for identity, capacity or a global
call lease is not partial; the first-request deadline still applies unchanged.

The implementation uses the existing official codec and crypto core, with no
private wire extension or replacement signing logic. Audio devices, helpers
and caller UI remain separate owners.
