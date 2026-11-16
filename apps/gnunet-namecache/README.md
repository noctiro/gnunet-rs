# gnunet-namecache

Inspect or delete one encrypted NAMECACHE block by public zone and name. The
command verifies the lookup signature and query, binds the block to the selected
zone/name, decrypts it and displays applicable records. Linux, macOS, FreeBSD and
Windows use the same client and interpretation flow.

## Usage and configuration

```sh
gnunet-namecache -c gnunet.conf -z PUBLIC_ZONE -n example
gnunet-namecache -c gnunet.conf -z PUBLIC_ZONE -n example --delete
```

`-z/--zone` accepts a PKEY or EDKEY public zTLD, `-n/--name` selects the name and
`-d/--delete` requests deletion instead of lookup. Standard PROGRAM configuration,
help, version and `-L/-l` options apply. The normal NAMECACHE CLIENT selection
supports configured TCP or native AF_UNIX; `--namecache-socket PATH` selects an
explicit local endpoint.

`--timeout-ms` defaults to 30,000 and accepts 1–3,600,000. `--record-profile`
accepts `native`, `little` or `big` for host-order Messenger record values; it does
not infer a remote producer's byte order or alter signed data. Positional
arguments are rejected.

## Results and resource limits

Lookup distinguishes absence, verified records and malformed/expired/invalid
blocks. Unsupported record values retain their numeric type and raw bytes.
Delete preserves the service's signed result code; negative results fail.
A source loss never causes automatic mutation replay.

One operation, RID and response are retained. Record interpretation uses
zeroizing buffers, at most 2,048 records, a 262,140-byte formatted value and an
8 MiB total output bound. Plaintext and opaque blocks are excluded from logs.
Output is bounded synchronous stdio; its native writes/flushes can block.
Partial output and flush errors fail explicitly.

## Ownership and cancellation

[Shared client startup](../../adapters/service-startup/README.md#client-program-startup)
rejects inherited listeners and retains original parent control. Native stop,
PROGRAM stop, logger failure, clock failure and Resolver failure end admission
and close the original MQ. Native and logical operation deadlines remain fixed.
Local cancellation retains Unsent/Partial/Written exposure and does not revoke
remote effects.

After a callback, the client connection closes before interpretation/output.
Error paths close before a separately bounded local completion drain and
Resolver disconnect. The PROGRAM foreground retains the original task through
scheduler failure so it can complete cleanup. Operation, cancellation, drain,
Resolver, output and logging errors remain distinguishable.

## Source layout

`main.rs` handles PROGRAM preparation and native startup. `foreground.rs` owns
one client/Resolver operation and cancellation; `settings.rs` validates command
options; `display.rs` owns bounded record interpretation and output.
`tests/normal_process.rs` drives the built command over literal IPC with public
zone/ciphertext vectors.
