# gnunet-service-zonemaster

Official per-user ZONEMASTER PROGRAM/SERVICE foreground source. It accepts normal shared PROGRAM options and no positional arguments; inherited listener/readiness and parent-control descriptors are adopted exactly once before configuration/logging/runtime. The official service has no domain IPC commands. `[zonemaster]` controls listener/ACL/USERNAME, worker count, DHT parallelism and publication window; `[namecache] DISABLE` controls the independent private ciphertext cache. Explicit resource ceilings are in `[zonemaster-rust]`.

The standard main installs `publish::DhtFactory`, using one shared DHT
client/reader with the same PROGRAM Resolver and clock. Public prepared query,
block bytes and expiration reach official PUT type11, replication5 and route
option1. Submission means original whole local MQ writing, never remote storage. Parallel flights/terminal notices, encoded source bytes and a single native
output frame have explicit bounds. Original deadlines, cancellation, shared-MQ
loss and canceled-write facts remain separate; issued one-shots never replay. The whole DHT source, including an idle MQ/connection attempt, closes
before CPU worker joining. Original terminal notices are moved into the Owner
stop report and returned foreground report, independently of canceled business
interests; error returns retain the same report. The main emits one aggregate
summary of local submission notices without claiming remote acceptance. The same foreground can accept an explicitly supplied
embedding factory without changing the protocol.
