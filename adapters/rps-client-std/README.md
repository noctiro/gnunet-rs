# Official RPS native client

`gnunet-rps-client-host` drives the ordinary configured CLIENT endpoint without
spawning a task or inventing an RPC. The caller supplies one `EndpointSource`
using its shared Resolver and RuntimeClock, and mints one original
`Bounds`. Retry before initial connection does not renew either original target. An established source is never transparently reconnected or replayed.

`Query::Sample { count }` writes the official stream request and feeds its biased
peer batches into the shared `gnunet_rps::ClientSampler`. Every original request
has independent random min-wise slots. Its concrete ports use native
entropy and standard HMAC-SHA512; a provider failure zeroes the refused output,
retains the original error, and ends that source without replacement entropy. `Sample` events expose sampler metadata, including the upstream zero
probability field, followed by `Complete` only after the local demand is met. Partial samples remain partial on loss. Count zero completes locally without
entropy or a socket. Raw `Query::Stream` records remain explicitly biased.

`Query::View { updates }` counts view frames: zero is continuous, a
positive number is a local exact quota. The service's opaque view ID is retained
without treating it as a request ID. `Record` owns the original frame and
selected reply-count ABI. The default ABI is explicitly the local target's C
ABI; use `ReplyCountProfile` to select a different known target. No count-profile
heuristic, fake request ID, ACK or wire END exists.

`new_in_group` writes the whole standard SubStart and then the ordinary
Sample/View/Stream request on the same physical MQ, before reading anything. `GroupWritten` and `Written` are separate local-write facts. The original
initial/overall deadlines cover that ordered startup. A group never moves to a
new source, and old input cannot become a new group's response. The C service retires that
membership when it observes this original MQ close. The helper `subgroup_hash` applies
the official GNUnet HKDF to the C-string prefix, salt `b"rps"`, no context. There is no invalid fresh-connection SubStop facade. `stop_sub` first sends
the original subscription cancel and then SubStop for this same original group
on the same MQ before physical close. Its partial/whole cancel and stop
byte counts remain independent local facts on failure.

Seed has a whole-write event only, with no remote processing or durability
receipt. Explicit subscription cancellation sends a standard same-source
ViewCancel or StreamCancel, then physically closes the MQ. If the
original request is partial, the owner closes it instead of splicing another
frame into those original bytes. `close` always performs local retirement;
neither operation claims that a server processed cancellation. Completed finite
observations also close their original source; `Complete` is the local quota or
sampler fact, never a remote enumeration END.

Frames, syscalls and sampler slots have explicit finite limits. Only the actual
request count is allocated; one peer per progress turn is fed into the
sampler, and the entire original batch is observed before eligible results are
extracted. IO waits, output guards, partial-frame deadlines and overall targets
remain owned across canceled await futures. Valid quiet subscriptions need no
fabricated first-row response. A synchronous syscall/entropy/HMAC call cannot
be preempted; the owner checks the original targets before and after each step. The enclosing output sink must also use `native_deadline` and preserve its own
flush/error result independently.
