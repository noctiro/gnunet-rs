# Core/host contract

All times are caller-supplied monotonic microseconds. `Instance::new()` lives
outside `Service<'i>`; create with `Service::new(&mut instance, local_peer,
main_hash, Config, Limits, now, random)`. Main hash is SHA512(b"rps").
No KDF is run by the core. SubStart supplies its already-derived wire hash.

`Random::fill(&mut self, &mut [u8]) -> Result<(), gnunet_types::Error>` must
supply fresh cryptographic randomness. `Rank::rank(&mut self, &[u8;64], &Peer)
-> Result<[u8;64], Error>` must implement HMAC-SHA512. Both are explicit ports.

`Config {view_size:usize, sampler_size:usize, round_interval:u64,
probe_timeout:u64}` defaults 10/10/30_000_000/30_000_000. `Limits {groups,
clients, peers_per_group, view, sampler, effects, retained_bytes}` are finite
usize bounds. Actual retained Vec capacities and in-flight payloads count;
transaction staging also must fit. No counts×maximum-names allocation.

`GroupId<'i>`, `Client<'i>`, `EffectId<'i>` are Copy, opaque instance-branded,
never-reused serial IDs. `main_group()`, `group_hash(GroupId)` identify real
port bindings. Destroy/recreate same hash always yields a different GroupId.

`attach_client() -> Result<Client>`; `detach_client(Client)`;
`client_request(Client, wire::rps::ClientRequest, now, random, rank)`;
`discover(GroupId, Peer, now, random, rank)`;
`peer_connected(GroupId, Peer, now, random, rank)` only for **remote**
authenticated channel/receipt evidence, never local channel-create Written;
`peer_message(GroupId, Peer, wire::rps::PeerMessage, now, random, rank)`;
`peer_lost(GroupId, Peer)`; `round(GroupId, now, random, rank)`;
`resize(GroupId, view_size, sampler_size, now, random)` accepts bounded NSE
size targets; `resize_all(view_size,sampler_size,now,random)` updates all active
groups and future subgroup initial sizes; `next_deadline() -> Option<u64>`; `round_due(now, random, rank)`.

`effect() -> Option<&Effect>` exposes the oldest unadmitted effect;
`admit_effect(id)` only after accepting its exact owned action into the host;
`complete_effect(id, Completion) -> Result<Terminal>` removes an originally
admitted effect, returning its owned original action plus original completion.
`reject_effect(id, Error)` retires an unadmitted action as Unsent. Completion
is Written, Unsent(Error), or Lost(Error); it is an IPC/transport fact, not a
remote semantic ACK. Close must retire every admitted host action explicitly.
`shutdown() -> Result<(),Error>` queues closes of ports/peers and retires clients without manufacturing
success. `is_closed()` stops admission; `pending_effects()` includes admitted
debts and `is_quiescent()` requires closed plus zero remaining effects. Old GroupId input is rejected, including old callbacks after recreate.

`Action`: OpenPort{group,hash}, ClosePort{group,hash}, Connect{group,peer},
ClosePeer{group,peer}, PeerSend{group,peer,message:PeerOutput},
ClientView{client,id:[u8;4],peers:Vec<Peer>}, ClientStream{client,peers}.
`PeerOutput`: CheckLive, Push, PullRequest, PullReply{peers:Vec<Peer>};
`PeerOutput::as_wire()` borrows the official frame. Client actions convert
through `Action::client_response()`; use explicit ReplyCountProfile in codec.
Actions have no invented ACK, END, RID, or sample-result frame.

Discovery issues bounded Connect + CheckLive + PullRequest. The pull
becomes reply-eligible only at its Written completion. A valid received
same-group/same-peer reply or authenticated inbound message grants qualification.
No CheckLive application reply is expected. Lost/Unsent original writes are
not replayed. Host loss of a source must call peer_lost with its original IDs.

ViewRequest immediately emits the selected current view; updates n>0 permits
n total replies including this initial snapshot, zero means continuous. ViewCancel ends only that local
interest. Stream has no END. Explicit cancellation suppresses queued unadmitted
responses; admitted old actions remain original host-owned terminal work.

ClientSampler::new(count, now, random); observe(peers,rank); next(now,random)
-> Result<Option<SampleInfo>>; remaining(). Each original SDK request owns its
sampler and request ID. Every slot requires >=2 biased-stream observations,
returns once, and refreshes its secret key when consumed. SampleInfo contains
peer, observed:u64, probability:f64 (0.0, as currently implemented upstream;
no probability/independence proof). Count zero completes locally with no wire.

ClosePort is an aggregate owner retirement: the host first physically retires all
channels of that original GroupId, preserves their original effect outcomes,
then closes that port and completes the original ClosePort effect. Known
peers without an channel do not create per-peer shutdown effects. Limits
require effects >= groups; when admitted originals temporarily occupy these slots,
stop new input, drain their terminals, and retry shutdown on Capacity.

Shutdown stops new admission and cancels unadmitted ordinary actions before
reserving close slots. Original admitted actions and already queued retirements
remain owned. Capacity can require draining those originals and retrying the
shutdown call; is_closed does not imply is_quiescent, which also requires no
remaining live group and no original effect debt.

`peer_closing(group,peer)` holds the original ClosePeer barrier until the host
has retired every old channel/input/pending frame for that group/peer,
then completes the original close effect. Discovery and incoming qualification
return WouldBlock during it; history/reply candidates being retired are skipped.
The host checks this barrier before old IO and keeps public hints for a new
independent probe after retirement. Old wire channel/epoch handles remain
subject to the native CADET owner; no new peer-generation wire field is added.
