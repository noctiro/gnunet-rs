# gnunet-testbed configuration utility

The active pinned executable supports `-n/--number NUMBER` and
`-t/--template FILENAME`. This PROGRAM frontend implements those operations
using shared GETOPT/CONFIG/PROGRAM and the native TESTBED owner. It accepts no
peer/controller operations because the current production target has none. Standard PROGRAM -c/help/version/log options retain their shared semantics.

```
gnunet-testbed -n 3 -t test-template.conf --output output-directory
```

Templates overlay the loaded default/PROGRAM configuration. The output
directory must already exist. Output uses 0000-<template-basename>, etc.; using a
safe basename avoids the C formatter's broken embedded absolute-template path. The exact original canonical home/config is really fsync-published first so
ARM.CONFIG and DEFAULTCONFIG resolve to bytes. Each canonical/export
publication has its own output line; a later failure is not reported as an
entire batch success. The process starts zero peer/service/helper processes.

Optional local utility controls are --prefix DIRECTORY, --output DIRECTORY,
--trusted-ip IP/CIDR, --hostname NAME, --low-port PORT (inclusive) and --high-port
PORT (exclusive). GNUNET_TESTBED_PREFIX is used when explicit --prefix is absent. This may name only a new/empty or exact Rust-marked private directory, never an
existing C peer/key store. Ports are past bind observations with logical
exclusion; output never claims future kernel exclusivity or service readiness. Configuration count is bounded1..4096 and required original port metadata is
precomputed before native creation. No unbounded diagnostics/output collection.

An error keeps already written configuration files and owned paths, reports the
original failure and independently attempted close/keep result, and exits1. Normal completion also keeps paths, matching the active command's purpose. Explicit library destroy(true) is available for an owning caller's later cleanup. Signals use ordinary process termination; there is no wire CANCEL or unknown
write replay. Atomic staging plus the original counter fence protects restart
from reusing issued home paths. Filesystem calls may block in the OS, and no
finite fsync/cancel guarantee is fabricated.
