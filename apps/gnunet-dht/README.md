# DHT commands

`gnunet-dht-get`, `gnunet-dht-put`, `gnunet-dht-monitor` and
`gnunet-dht-hello` use the configured official DHT IPC client. They share one PROGRAM lifecycle, configuration, clock, Resolver and cancellation
owner. No DHT service or peer network is started by these commands.

The official key, replication, route, block type, GET timeout and PUT expiration
options follow v0.29.1. PUT additionally accepts `-T` to bound its total wait. GET defaults to 60 seconds; PUT records default to a one-hour expiration. `-K`
decodes the 103-character printed key; otherwise the exact input is SHA-512 hashed. GET consumes matched results, retaining one bounded output buffer before
accepting another. Route output is unverified metadata from the DHT service.

A PUT succeeds only when its original local MQ frame is fully written. There is
no official PUT acknowledgement; loss never causes an automatic replay. An empty
DATA value is rejected like the official client API. Native signal/parent stops,
clock changes, Resolver failures, timeout and original client close share the
same cleanup path. No runtime or official interoperability result is claimed by
the presence or compilation of these commands.

`gnunet-dht-monitor` observes GET, PUT and RESULT notifications, with an
optional exact key and block-type selector. Its key is decoded as Base32 first,
then hashed on decode failure unless `-K` requires a raw key. The default is
60 seconds. Message expiration is printed in absolute microseconds.

`gnunet-dht-hello` without arguments obtains the public HELLO URL (or its
explicit absence). A single positional URL offers it, using the existing
metadata signature/expiry checker; v0.29.1 does not authenticate its addresses. An offer completes only after its original IPC frame is written. HELLO defaults
to an unlimited wait and adds `-T` for an optional finite total budget. A native
MQ loss may restore an observation, and never replays an offered URL.
