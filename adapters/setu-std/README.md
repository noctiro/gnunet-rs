# Official native SETU service adapter

Drives the `gnunet-setu` service over shared application IPC and one CADET
client MQ. See the [service guide](../../apps/gnunet-service-setu/README.md)
for configuration and process lifecycle.

`Server::new(core, cadet, limits, options, unix)` owns one pure service, one real
CADET client and fixed native metadata slots. The foreground owns the CADET
Instance/PortSlot/ChannelSlot vectors outside the server, avoiding self references
or hidden allocation-backed tasks. The server obtains the endpoint clock
from that original CADET client. The standard foreground uses a single explicitly
owned process Resolver and drives it alongside this server; neither dependency
is implicitly spawned by this adapter.

`admit` accepts only a canonically initialized AcceptedConnection. Native
socket diagnostics are forwarded. TCP ACL and kernel Unix UID/GID policy run
before core.connect; UID priority comes from shared UnixAccess. `poll`/`drive`
fairly advance app reads/writes, CADET IO, original pure effects, peer
processing, results, algorithm work and listener acceptance. There is no worker
or disk IO. One poll performs a bounded source/work action; algorithm size bounds
remain the explicitly configured core limits, rather than a constant-time claim.

Every app source has shared Framed RX/TX, immutable queued output and one bounded
held frame. Each queued/held frame retains its original admission deadline and
checked local tag. Partial reads have an original finite deadline started at the
first positive read, with no reset after subsequent bytes. Output and partial
input deadlines close the app socket before client_closed. An impossible
ADD element is refused at that source when it cannot fit CADET's official
MAX_APPLICATION_MESSAGE_SIZE wrapper; there is no private fragmentation protocol.

Every CADET bind/open/channel/close stays associated with the original branded
pure client/operation and original CADET Port/Channel/Transmit/Delivery. One native
pending frame retains its original transmit/action and finite physical deadline. Manual writes and automatic reconnect port announcements/rejections share that
same bounded ownership; a cancelled observation future drops none of it.

- Listen waits for PORT_OPEN complete writing (or restoration) then
  reports listener_ready. A live logical port can be reannounced by the existing
  CADET client after physical MQ loss. App retirement requests its original
  Unlisten; PORT_CLOSE full writing, or known unannounced retirement after
  old MQ loss, precedes listener_closed. A late racing incoming channel is really
  destroyed, without substituting a new listener or terminating another port.
- Open retains an original unsubmitted intent until native admission. Actual
  CHANNEL_CREATE writing binds core.connected to that channel's expected
  peer metadata. Official CADET IPC has no create-acceptance ACK. No remote
  acceptance is inferred: DATA still requires the service's channel credit.
- Send copies the exact immutable core frame once into its original channel's
  held lease and submits it only with CADET credit. Only exact Written
  Transmit completion calls core.sent for the original Transmission. Cancellation
  retains an admitted suffix on the old MQ; it is never replayed after loss.
- Incoming uses the CADET channel/port and service-supplied peer. The first
  original operation frame is associated with the original listening app,
  keeping the deadline from channel admission. All complete nested frames in an
  outer DATA retain their original packet/cursor across backpressure. receive_done
  is admitted only after every original nested frame was accepted by the core,
  then its written ACK is counted separately from peer delivery.
- Close stops unsubmitted sends but drains an admitted original frame, then sends
  CHANNEL_DESTROY. This official one-way command has no reply ACK; its actual
  full write retires that local channel generation. Actual remote destruction
  preserves earlier complete held DATA until the original operation accepts its
  nested frames, then waits for any admitted native suffix for that channel to
  settle before the core retirement callback. A gone channel grants no new peer
  send or receive_done/ACK: its fully consumed packet is released locally. Known
  cancellation, malformed input and expiry still abandon input and preserve the
  failure; destruction alone never supplies missing protocol success.
  Original channel wire numbers/generations are never rebound to new operations.
- A permanent stall in a native control/data write, partial read, retained blocked
  input or channel/port retirement reaches its original physical grace. The
  adapter really detaches/reconnects the one original CADET MQ before retiring
  all old channels. It emits the Lost epoch/prefix report. Desired live
  ports can restore, while application operations/payloads never replay. Actual
  IO/configuration/clock failures retain their concrete error and are not replaced
  by a fabricated timestamp, ACK, known-unsent result or successful close.

Operation deadlines use the endpoint's logical source clock and one
exclusive earliest Deadline listener. Absolute targets do not reset on retries
or rollback. Physical partial/retirement budgets use explicit Tokio Instant
limits and one shared native timer; they are separate cleanup bounds, not fake
logical now. Idle complete app sets/listeners remain valid; only incomplete or
queued work has these finite drain limits.

Soft shutdown stops new admission and allows app owners to exit; the
foreground enforces finite SHUTDOWN_GRACE and always calls `shutdown`. Immediate
`shutdown` physically closes every app stream and the CADET MQ before consuming
pure callbacks, even if the source clock/Resolver/peer has failed. The actual
CADET loss event preserves pending exposure facts. All independent sources are
attempted, and the first cleanup failure is returned. A nonquiescent pure owner
is a failure, never a successful STOPPED receipt. Drop uses the same physical
cleanup without creating another task or resetting a timer.

The package enables gnunet-setu/zlib explicitly for this host. The default pure
SETU/embedded SDK graph stays without alloc; the independent SETU native CLIENT
feature must not implicitly enable this SERVICE or its foreground.

IBF slices fit the 64348-byte CADET application-message limit; larger transfers
are split by the existing bounded operation owner.
