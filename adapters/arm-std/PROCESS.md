# Shared native process owner

ARM-self delegates to the one implementation in
[gnunet-service-runtime](../service-runtime/PROCESS.md). The ARM package retains
its configuration/libexec/source outcome thin layer and the dedicated helper
binary; it contains no copied native process or readiness backend.

The current helper envelope directly carries filename separately from argv0.
No old internal envelope branch or compatibility migration is retained.
