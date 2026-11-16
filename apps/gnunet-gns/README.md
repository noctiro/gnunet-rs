# GNUnet GNS command

Resolve names through the configured GNUnet GNS and IDENTITY clients. Linux,
macOS, FreeBSD and Windows share name routing, record projection and cancellation.

## Usage and configuration

```sh
gnunet-gns -c gnunet.conf -u NAME -t A
gnunet-gns -c gnunet.conf -u NAME -t TXT -r -T '5 s'
```

Standard PROGRAM configuration, help, version and `-L/-l` options apply. The
name before the first colon is used. Record type defaults to A; unknown type
names warn and select ANY. `-d/--dns` validates DNS syntax and converts IDNA to
UTF-8 before GNS routing; it does not perform a DNS fallback.

A real NotGns classification exits 4. Empty GNS answers succeed. DNS validation
and IDNA conversion retain the reference exit classifications 3 and 4. Setup,
query, output and cleanup errors are nonzero.

## Deadlines and output

The default total timeout is forever. A finite `-T` captures one native target
before its first canonical clock sample; routing, retries, callbacks and output
cannot renew it. Native termination, parent control and PROGRAM cancellation
close the same query and Resolver owners without replaying exposed requests.

Raw mode prints values. Normal mode also prints record types, supplemental flags,
count and elapsed time. Values that cannot be formatted are diagnosed and skipped.
Records are observations from the selected service; zone authentication belongs
to that service.

The name is bounded to 1,024 bytes and replies to 65,535 bytes/2,048 records.
Formatting uses two buffers of at most 262,140 bytes. `[gns-cli] MAX_OUTPUT_BYTES`
bounds the complete output: default 16 MiB, configurable from 1 byte to 64 MiB.
The output buffer grows geometrically within that bound.

[Shared native I/O](../../adapters/program-std/BINARY_IO.md) admits one 16 KiB
output chunk at a time. Windows consoles receive Unicode; redirected bytes stay
exact. The foreground keeps driving query, Resolver, stop and deadline events
while the original worker performs native output. No shared file-status flags
are changed. Partial writes advance only their confirmed prefix.

## Ownership and source layout

`main.rs` composes PROGRAM and keeps output retirement outside its cancellable
task. `early.rs` delegates to shared client startup; `control.rs` owns the stop
latch and subscriptions. `run.rs` retains one with-TLD query and its independent
cleanup results; `budget.rs` owns the original time bounds. `output.rs` projects
records and drives output; `output/retirement.rs` retains actual transfers and
flush/close observations under one separate one-second cleanup deadline.

Canceling a wait does not cancel or replay an admitted native write. Late or
unclaimed completions and native flush/close errors remain failures. Diagnostics
exclude record bodies. The [with-TLD API](../../adapters/gns-api-std/README.md)
retains protocol routing below the command.
