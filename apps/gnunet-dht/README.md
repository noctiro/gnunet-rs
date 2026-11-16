# DHT commands

`gnunet-dht-get`, `gnunet-dht-put`, `gnunet-dht-monitor` and
`gnunet-dht-hello` use the configured official DHT IPC endpoint. Their shared
PROGRAM lifecycle owns configuration, clock, Resolver and cancellation on Linux,
macOS, FreeBSD and Windows. These commands connect to an existing DHT service.

## Configuration and options

The `[dht]` endpoint uses the shared [client configuration](../../adapters/client-std/README.md).
Standard `-c`, `-L`, `-l`, `-h` and `-v` apply. Key, replication, route, block type,
GET timeout and PUT expiration options follow GNUnet v0.29.1.

```sh
gnunet-dht-put -k example -d value -T '10 s'
gnunet-dht-get -k example -T '10 s'
gnunet-dht-monitor -T '10 s'
gnunet-dht-hello -T '10 s'
```

GET and PUT default to a 60-second wait; PUT expiration defaults to one hour.
`-K` decodes a 103-character printed key; otherwise the exact key is SHA-512
hashed. Empty PUT data is rejected. `-R` records routes and `-x` enables
demultiplexing. Route output is unverified service metadata.

MONITOR observes GET, PUT and RESULT notifications with optional key and
block-type selectors. It tries Base32 first, then hashes on decode failure
unless `-K` requires a raw key. Its default wait is 60 seconds; message
expiration is printed in absolute microseconds.

HELLO without arguments obtains a public HELLO URL or its explicit absence.
One positional URL offers it using the existing signature/expiry checker;
v0.29.1 does not authenticate HELLO addresses. The default wait is unlimited;
`-T` supplies a finite bound.

## Completion and recovery

PUT and HELLO offers complete only after their original local MQ frame is fully
written. PUT has no official service, replication or durability acknowledgement.
MQ loss may restore observations but never replays an issued PUT or offered URL.
Native stops, parent control, clock changes, Resolver failure and timeout use
the same cleanup path.

## Output ownership

GET and MONITOR retain one bounded result before admitting another delivery.
A capacity-one native byte writer preserves arbitrary TEST payload bytes on all
platforms. Only actual native completions advance its cursor. Stops and expiry
end output admission; cleanup retains any submitted write and observes transfer,
flush and close under one three-second bound. A pending write is never reported
as canceled, and independent output-retirement failures fail the command.
