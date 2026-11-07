# Foreground native NSE service

Run `gnunet-service-nse -c official.conf`. The executable captures activation
before runtime setup, loads official configuration through the shared loader,
composes native CORE/PILS and a fenced raw8 proof writer, and accepts NSE
START subscriptions on the common configured/inherited listeners. It prints
READY only after verified PILS/CORE identity agreement. SIGINT/SIGTERM stop all
original physical owners and flush pending proof progress before exit. Normal configuration uses WORKBITS15, INTERVAL1h, WORKDELAY5ms and PROOFFILE. This executable never launches a C implementation or an implicit Resolver task.

The original activation and parent-control descriptors are captured as the first
startup operation. After loading the configuration, the executable resolves
`[NSE] USERNAME` and applies the shared native primary/fallback privilege
sequence, including the normal initgroups profile, before creating its runtime,
workers, proof store, native clients or listeners. Failure exits immediately;
no rollback or stronger saved-ID/capability guarantee is implied. The report
records the identity and route. Callers embedding the async foreground
must apply the selected account before their own runtime/workers; the foreground
only verifies real/effective UID/GID and refuses a mismatch before opening
service resources.

`[NSE] UNIX_MATCH_UID=YES` requires the original Unix stream's kernel peer UID
to match the service effective UID and takes priority over `UNIX_MATCH_GID`. When only GID matching is enabled, the common kernel-primary/native-membership
policy is used. Missing flags are false and malformed flags are configuration
errors. Checks happen before framing or pure NSE START allocation, with actual
per-stream errors preserved. TCP uses the existing configured ACL. Path
permissions still determine whether a client can reach a Unix socket. A local
rejection closes only that new stream and does not resume an EMFILE-suspended
listener.
