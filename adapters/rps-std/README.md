# Native RPS SERVICE/CADET owner

`gnunet-rps-host` owns the accepted RPS IPC sources and one caller-provided
`gnunet-cadet-host::Client`. The foreground owns both Instance brands, the
runtime, listener/config/Resolver domains, and the CORE identity,
PEERSTORE/CORE discoveries and NSE estimates. No worker, hidden task, self-RPC or
second network stack is created. `Server::new` takes the original pure Service,
CADET client, Limits, ServiceOptions and UnixAccess; `poll`/`drive` retain all
partial cursors when an observation future is canceled.

Each branded port maps to its original GroupId. Each channel retains its
original CADET channel, group and channel-supplied peer. Incoming data is decoded
from that original Received envelope, one nested message per turn. The actual
Delivery is acknowledged through receive_done only after all its messages have
been handled; an enqueued receive_done is not a written receipt. Local channel
CREATE or CHECK_LIVE writes never qualify a peer as remotely live. Recreated
same-hash groups wait for the old branded port to retire. Core peer_closing
barriers revoke old channel work before another native poll and prevent an old
peer_lost callback from removing a replacement probe.

Every original core effect remains retained until a matching native
terminal. IPC responses preserve immutable snapshots, original client IDs and
FIFO write tokens. Peer payloads use an original channel generation and only
service send credit. Written is reported only from the original complete
Framed/CADET write token. A zero-exposure original source loss is Unsent; partial
or uncertain exposure is Lost. A locally absent/retired port is not given a fake
port-close Written. Native causes and original terminal metadata remain separate. No sampler-result, request ID, protocol ACK or END frame is invented.

Default bounds are 64 IPC sources, 16 group ports, 256 channels and 4096
retained public discovery facts. IPC frames are at most65535bytes with four
responses/262140retained payload bytes per source; queued peer payloads are at
most1024frames/8MiB Vec capacities. These payloads allocate with actual
traffic, not maximum-width arrays per record. Runtime framing and CADET have
additional explicit original frame limits. Each source has a30second first
input bound,15second partial/retained-input phase bound and5second immutable
write/retirement bound. Bounds never reset on positive partial progress. A slow
IPC source is physically retired independently. A canceled/expired partial
CADET write retires that original shared MQ because its prefix cannot be moved
to another source. These are resource policies, not measured throughput/RSS.

`ready`/`initialized` requires an attached CADET MQ and a fully announced
current main port. It says nothing about remote peer reachability or samples. Public discovery facts survive loss only as bounded seed facts; a replacement
source issues fresh probes/effect IDs. Old payloads are never replayed. `discover`, `discover_main`, `resize`, `resize_main`, `resize_all` and
`forget_seed` accept foreground observations. An identity/source change
requiring a different local peer must retire this original Server and Service.

`ports::NativeRandom` uses getrandom, zeroes a failed output and retains the
first original provider error. `HmacRank` uses the existing HMAC-SHA512 primitive. `main_group_hash` is SHA512(b"rps"); `subgroup_hash` uses the existing GNUnet
compatibility HKDF with salt b"rps", the shared C-string prefix and no context. The wire's explicit C reply-count ABI selector is preserved.

Shutdown stops admission and physically closes every original IPC/CADET source
before dropping native debt. It settles known Written/Unsent/Lost work, drains
unadmitted payloads and retries only the core's closing algorithm after original
capacity is released. Groups close through the aggregate ClosePort effect,
including all same-group channels. The owner reports Stopped only when
all physical/native owners and original pure effects are quiescent. Irrecoverable
original/cleanup errors remain available; unresolved backpressure leaves the
same owner available for another clock-free shutdown call.

A later CADET Destroyed preserves already-owned input under its original
partial-input and retirement bounds. Local cancellation, group/peer retirement,
error and expiry still discard that input. With another live same-peer/group
channel the original normal handler applies. After the last source closes, only
a PullReply matching an original actually-written PULL retains third-party hints;
the shared core candidate path performs ordinary probes and atomically
removes the gone sender without new online, stream or sampler qualification. Sender-only PUSH/CheckLive observations and unanswerable PULL requests do not
revive it. Completed gone-channel packets are released locally without ACK. New sends never select a gone channel; original admitted native frames keep their
whole/loss/unsent receipts and deadlines. Other channels' MQ credit keeps
progressing; no whole-MQ read freeze or fabricated sample/completion is added. The atomic closed-reply transition marks only its existing original channel
owners as qualification-retired. Their later native cleanup cannot remove a
fresh same-peer probe; new channel owners start unretired and original effect
IDs still gate any late completion. A qualification-retired owner discards any remaining held input, so an old
packet cannot match a newly written same-peer PULL after retirement.
