# gnunet-service-zonemaster

Official per-user ZONEMASTER PROGRAM/SERVICE foreground. The service has no
domain IPC commands. Its [native composition](../../adapters/zonemaster-std/)
owns NAMESTORE monitoring, durable nonce reservations, Rust crypto workers,
public DHT publication and private NAMECACHE updates.

## Configuration and startup

The Unix and Windows entries accept shared PROGRAM options and no positional
arguments. Inherited listeners and original parent status/control are captured
once before configuration, logging or runtime creation. Unix applies configured
privileges; Windows verifies the configured process token and adopts native
activation. This PROGRAM entry has no SERVICE daemon option.

`[zonemaster]` controls listener/ACL/USERNAME, worker count, DHT parallelism and
publication window. `[namecache] DISABLE` controls the private ciphertext cache;
`[zonemaster-rust]` holds resource ceilings and the durable nonce directory.

```sh
gnunet-service-zonemaster -c gnunet.conf
```

Readiness follows listener and worker-owner construction. Windows submits its
original parent status under a finite deadline while observing the selected
Reporter and original stop source. A canceled notification cannot replace an
admitted status. Normal stop and logging failure retain the original owners
through shutdown; Resolver disconnect errors remain attached to the result
even when PROGRAM cancellation drops its task.

## Publication lifetime

The standard main installs `publish::DhtFactory`, using one shared DHT
client/reader with the same PROGRAM Resolver and clock. Public prepared query,
block bytes and expiration reach official PUT type11, replication5 and route
option1. Submission means original whole local MQ writing, never remote storage. Parallel flights/terminal notices, encoded source bytes and a single native
output frame have explicit bounds. Original deadlines, cancellation, shared-MQ
loss and canceled-write facts remain separate; issued one-shots never replay. The whole DHT source, including an idle MQ/connection attempt, closes
before CPU worker joining. Original terminal notices are moved into the Owner
stop report and returned foreground report, independently of canceled business
interests; error returns retain the same report. The main emits one aggregate
summary through the selected Reporter without claiming remote acceptance. The same foreground can accept an explicitly supplied
embedding factory without changing the protocol.
