# Native official DHT client

`gnunet-dht-client-host` combines the independent DHT logical owner with the
shared CLIENT `EndpointSource`, `ConnectionAttempt`, canonical `RuntimeClock`
ports and `Framed` IO. The caller drives one bounded observation at a time. It
creates no DHT service, Resolver task or hidden scheduler loop. This package is
not imported by the default SDK.

Dropping `drive` preserves original connect attempts, partial RX/TX and logical
intent. Closing or reconnecting first retires native IO; outstanding one-shot
notices retain their original MQ owner. Port failures remain retained until
explicit recovery. A closed client cannot allocate another listener.

`Progress::Written` and one-shot `Outcome::Written` are local byte-transfer
observations. Neither proves DHT acceptance, network delivery or persistence. No peer identity is inferred from a connected Unix socket. `Received` owns a
complete bounded observation and offers borrowed official decoding.

`poll_with_input(cx, deadline, receive)` exposes the same owner to callers with
bounded input capacity. With receive=false, it neither reads nor dispatches
complete retained input; original clock, connection, output/partial FIFO and STOP
progress remain enabled. The caller polls again when its input capacity opens. The existing `drive` wrapper uses receive=true. A wait deadline remains an
observation bound, not proof of cancellation or physical quiescence.

`take_completion` consumes an already-retained original one-shot notice without
sampling a new clock or performing IO. A caller can observe Written/Lost
before deciding whether a still-live operation requires cancellation.

The Unix tests force one byte per IO, one output frame and one original attempt. They exercise partial GET cancellation followed by its exact STOP, canceled
wait futures with retained partial responses, PUT cancellation, truncated EOF,
fresh-MQ reconstruction and no uncertain PUT replay. Port tests check retained
clock refusal and listener release.

The `normal_dht` example is an interoperation probe for an independently started
normal official v0.29.1 DHT profile and its public C API actor. Its fixture keys,
payloads and cached Reference029 identity are deliberate assertions. It exercises
bidirectional data exchange, HELLO metadata verification/offer, monitors,
GET/known/monitor restoration and STOP. The independent evidence capsule records
the exact official build, actors, original failures, inputs and runtime images. That single-node TEST-plugin/heap-cache profile is local IPC evidence, not a
remote-routing or durability claim.

`retire_io` physically detaches the original MQ or pending connection attempt
without a clock sample or replacement IO. A present epoch settles its original
one-shots as Lost; their terminal notices remain available through
`take_completion`. A missing epoch returns None and does not assert that no
native connection attempt existed. Later explicit driving can create a fresh MQ
for safe retained reads or independent new operations; issued PUTs never replay. Permanent `close` remains separate and disables further operations.
