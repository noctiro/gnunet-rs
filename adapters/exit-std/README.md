# Actual native EXIT runtime adapter

This package implements a callable production adapter over the existing
CADET CLIENT, verified TUN/utun owner and literal-resolver UDP sockets. It does
not create a detached task/thread, C helper/process wrapper, private protocol,
route, address configuration, advertisement or discovery result.

Driver::new(engine, fresh_cadet, Option<OwnedTun>, bindings, resolver, limits,
entropy) consumes native owners and fixed resources. The foreground owns
the CADET Instance/PortSlot/ChannelSlot vectors outside the borrowed Client,
avoiding self references. The TUN descriptor must already be genuinely verified
by gnunet-tun-host; this adapter registers it on the current shared Tokio reactor. DNS-only EXIT may supply None and requires no TUN. A non-DNS binding without an
device is refused. Fresh/idle CADET ownership is required; no old pending
byte cursor or logical operation is adopted from another driver.

The canonical source clock comes from the CADET endpoint. Caller-provided
Entropy remains explicit; OsEntropy uses getrandom at admission and keeps
its original provider error for take_failure. No fallback timestamp/nonce/random
value is generated. No C private-key file is read or hashed.

## native boundaries

poll/drive fairly run the original CADET MQ, peer frames/processing receipts,
core effects, whole TUN reads/writes, DNS sockets and physically settled flow
observations. Dropping a waiting future leaves the same owners/cursors/packets
inside Driver. Shared PROGRAM/startup/configuration/privilege and Resolver setup
remain the foreground's job; the adapter takes explicit native owners instead
of starting a second runtime, resolver, service IPC or administrative helper.

remote channel destruction retains only the DATA already held on that
original channel/Flow. Its inner cursor waits for the existing forwarding
receipt: a whole original DNS query write or the TUN packet completion. It does not wait for a DNS response. The exact DNS socket is then retired when
its peer is gone; a late response has no consumer and creates no peer reply. Only after those original inner receipts finish, or local cancellation or
expiry revokes them, is the Flow finally closed and processing debt retired. No new receive_done/ACK or peer DATA is admitted on the gone channel. Other MQ
channels and credits remain pollable, and already admitted native suffixes keep
their original Written/loss accounting.

The gone-packet drain has a canonical/native target captured at DATA
receipt from the existing core input_lifetime. Destruction cannot reset it;
the existing native io_grace and any earlier local hard also intersect it. Expiry of that gone-input bound revokes only its original held work and starts
local Flow cleanup. It cannot close the shared CADET MQ. An actually pending
native frame/read or a still-live channel's destroy retains its own original
MQ hard; those physical obligations are independent of the gone drain. This target applies only to the gone drain, preserving ordinary live packed
input timing. Local close, input/flow expiry and source/device loss still win;
the original flow, packet bytes, external task IDs and deadlines never move to
another peer.

Official bindings use gateway_port(exit-ipv4/exit-ipv6), the configured exact
service hash or SHA512(exit-dns). Arbitrary replacement hashes are rejected. Actual PORT_OPEN writing comes from the CADET client. Incoming channel metadata
uses the channel/port/peer supplied by that exact physical MQ. Each flow is
bound to the Engine Source corresponding to the CADET epoch. Tuple/NAT/
packet/checksum/ICMP/TCP/DNS business behavior remains in the shared pure core.

DATA sends need CADET credit. The original Engine Write is retained while
unsubmitted, then mapped to the exact original native Transmit. Only matching
Written calls peer_written. A pending body cannot be spliced, discarded as
known-unsent, moved to another channel or replayed on reconnect. Original native
partial/read/blocked/control deadlines really close/reset that MQ before source
loss consumes old flow/ACK/output debt. Logical live ports can restore through
the existing client, while old application payloads never replay.

CADET outer DATA may contain multiple inner GNUnet frames. Each inner frame is
admitted to its original flow, waits for the TUN/DNS forwarding completion,
then transfers its exact ready+issued Input to the bounded processing table. The original outer packet/cursor and all exact Inputs remain in Driver. Only
when every original inner frame has really been processed can the one original
outer Delivery enter receive_done. Only its Written acknowledges
all those Inputs. Channel close keeps an admitted ACK suffix until it drains or
the MQ closes; no processing event is silently turned into an early ACK.

The included minimal core patch adds processing_receipts capacity, the original
processing_batched table and processing_capacity. A capacity refusal leaves the
same ready+issued current Input untouched. It remains an ACK debt, not a retired
receipt. Actual acknowledged/processing_retired/source_lost are the only ways
out. Driver validates channels*inner_frames <= this capacity before IO, preventing
a circular wait where every packed outer packet consumes only part of the table. No private field is added to GNUnet wire and existing single-frame behavior stays.

TUN output uses exactly one gnunet-tun-host whole-packet queue. Real WriteId and
Epoch are mapped to the original Engine Tun/Write. Written means the full
framed syscall succeeded. Unsent is accepted only from a true native zero-byte
retirement or a never-admitted driver request. A positive short write really
closes the old descriptor and reports OutcomeUnknown through tun_lost; no suffix
is sent as a new packet. Received normalized raw IP keeps its original verified
epoch through bounded backpressure. Explicit packet drops are observable and
never become successful forwarding/receive_done. After TUN loss, Internet/service
bindings are disabled and actually withdrawn; DNS can continue independently.

DNS jobs have a fixed maximum number of fresh owned UDP sockets. Every job keeps
its original Dns token, immutable query/id, exact literal server and original
absolute/physical target. Socket bind/registration must really succeed before
engine.dns_admitted. Only a whole send calls dns_written; retries keep that
same socket/job/query/id until its original target. Reads validate the actual
server IP/port/IPv6 scope, DNS ID, QR, opcode and bounded canonical question list
using the existing DNS Reader. Invalid datagrams are consumed/discarded, not
reported as another job's answer. A response is copied before receive storage is
reused, and retained across core backpressure. Cancellation/error/timeout drops
that original socket before dns_retired; no NXDOMAIN or other synthetic
negative answer is created. There is no socket generation reuse across jobs.

## Clocks, cleanup and caller ports

The driver checks source-clock regression and returns TimeUncertain; it
does not replace now. One logical earliest Deadline and one shared native timer
wake the caller. Original input/output/DNS targets never reset on retries. Native grace begins once at the original effect boundary. Per-source IO errors
retain their cause and scope. A caller must finish errors with shutdown.

request_shutdown requests the original per-flow/DNS/source/device effects. Synchronous shutdown independently closes the CADET MQ, TUN and all DNS
sockets before reporting callbacks, even when the clock/peer/Resolver has failed. It attempts every cleanup and returns the first refusal plus the core's
quiescent state. Drop uses the same cleanup. A close flag or expired TTL
is never accepted as evidence that old native bytes/sources have retired.

binding_status is the explicit readonly port for an independently owned external
advertiser. announced only describes local PORT_OPEN writing on the current
MQ; it says nothing about configured routes, global reachability, remote app
acceptance, regex publication or DNS-exit DHT advertisement. Their work is neither resumed nor renamed as EXIT work.

The [EXIT foreground](../../apps/gnunet-daemon-exit/README.md) supplies process
startup, privilege handling and device/address/route provisioning. The adapter
requires verified native owners and explicit shutdown before exit.

## Bounds

Defaults are32 ports,64 channels,64 inner frames per outer DATA,32 DNS jobs,
4096 DNS bytes,16 questions,5s original native IO/held-input grace and30s first
channel input. The core's default processing table is16,384 metadata entries,
allocated only as used. DNS buffers/sockets and original outer receipt vectors
have independent explicit bounds. No extra registry version is introduced;
alloc is enabled only in this explicit native host graph.
