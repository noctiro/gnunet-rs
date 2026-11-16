# gnunet-testbed configuration utility

`gnunet-testbed` creates unique GNUnet configurations from a loaded template on
Linux, macOS, FreeBSD and Windows. PROGRAM supplies configuration, filename
expansion, help/version and logging. Generated peer homes and canonical configs
are kept for subsequent service startup.

## Usage

```sh
gnunet-testbed -n 3 -t test-template.conf --output output-directory
```

`-n/--number` selects 1–4096 configurations; `-t/--template` selects the template
to overlay on PROGRAM configuration. The output directory must already exist.
Exports use `0000-<template-basename>`, `0001-<template-basename>`, and so on.
Each generated canonical home/config is published before the export that refers
to it through `ARM.CONFIG`. The in-memory `PATHS.DEFAULTCONFIG` also selects
the canonical file. Official CONFIG serialization omits that loader-derived key;
a reloaded export initializes it from its own selected filename.

## Configuration

Optional controls are `--prefix DIRECTORY`, `--output DIRECTORY`,
`--trusted-ip IP/CIDR`, `--hostname NAME`, `--low-port PORT` (inclusive) and
`--high-port PORT` (exclusive). `GNUNET_TESTBED_PREFIX` applies when `--prefix`
is absent. A selected root must be new, empty or exactly marked by this utility.
Native paths and Unicode names use the shared CONFIG representation.

Port assignments are past native bind observations plus logical batch exclusion.
A later service must still acquire its sockets. The command reports canonical
and exported publications separately, including completed file synchronization
and the native directory barrier observation. Windows directory synchronization
can be unavailable. The host's [ownership and publication contract](../../adapters/testbed-std/README.md)
describes restart, resource limits and explicit tree removal.

## Cancellation and failures

Native client startup captures original inheritance before other resources.
Unix signals, Windows console stop events and parent control stop admission
between bounded generation/publication steps. Synchronous filesystem calls can
block and cannot be forcibly preempted. Existing publications and owned homes
remain available after cancellation or a later error; issued path numbers are
not replayed. Operation and independent cleanup errors remain distinct, and
failure returns a nonzero exit status.

The executable generates files and releases its logical reservations; callers
start and manage peers through ARM or the service runtime.
