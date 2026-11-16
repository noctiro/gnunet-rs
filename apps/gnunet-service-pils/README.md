# PILS service

`gnunet-service-pils -c official.conf` runs the Rust implementation of official
PILS. It loads `[PEER] PRIVATE_KEY` as an exact raw32 seed and uses no C backend.

## Configuration

The shared SERVICE options are `-c/-d/-h/-L/-l/-v`; `-v` prints the version.
Official listener, ACL, USERNAME and UNIX_MATCH_UID/GID settings apply.
`[PILS] PROFILE` selects `reference029` or the official conditional
`deterministic` identity profile. See the [host API](../../adapters/pils-std/)
for private-file, profile and framing contracts.

## Native startup

Unix captures activation/control descriptors before options and performs explicit
fresh-process detachment before runtime or key setup. TCP/activation preparation
precedes the configured identity transition; new local paths finish afterwards.
Windows captures native activation/bootstrap first, verifies the configured SID,
and uses the shared qualified parent and detachment owners.

Both entries register native stop subscriptions before private-root preparation,
then drive one common foreground with the same bounded authority host and selected
Reporter. The original lock/key handles stay owned until service keys erase.
File synchronization and directory-barrier availability remain separate facts.

## Readiness and shutdown

`READY <public-key-hex>` is flushed after the real authority and listeners exist.
The original parent notification has one fixed bounded wait with native stop and
diagnostic observation. Failure or early stop cannot become a ready receipt.

Termination or diagnostic failure closes actual streams before erasing keys and
releasing the writer lease. Per-source failures remain isolated. Original service,
logging and final output errors survive cleanup; `STOPPED` contains public counters.
The [compatibility contract](../../spec/gnunet/compatibility.md) defines broader
interoperability qualification.
