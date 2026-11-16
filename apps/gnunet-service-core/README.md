# CORE service

`gnunet-service-core -c official.conf` runs the Rust CORE service over verified
PILS announcements and the configured TRANSPORT client endpoint.

## Configuration

Shared SERVICE options are `-c/-d/-h/-L/-l/-v`; `-v` prints the version.
`[core]` selects listeners, ACLs, CLASS and USERNAME. `[pils]` and `[transport]`
select dependencies; `[PEER] PRIVATE_KEY` names the existing official raw32 seed.
`[PILS] PROFILE` selects one explicit announcement/signature interpretation.
See the [host API](../../adapters/core-std/) for session, credit and crypto contracts.

## Native startup

Unix captures transferred descriptors before other initialization and detaches
at the fresh-process boundary. Original TCP/activation preparation precedes
USERNAME/initgroups; deferred local paths finish under the selected account.
Windows captures native activation/bootstrap, verifies the configured process
SID and registers the qualified parent and native stop subscriptions.

Both entries retain completed listeners in `PreparedService` and drive one
foreground with the selected Reporter and clock. No async task changes process
identity. Existing account permissions must permit private-key access.
Unix credential options use native UID/GID checks. Windows local paths use native
ACLs; an explicit Unix UID/GID request remains unsupported without fabricated IDs.

## Readiness and shutdown

`READY <public-key-hex>` is flushed after the actual PILS signature, context and
local derived identity have been verified and the CORE host exists. The original
parent notification is bounded by one native deadline and the same stop/Resolver
owner. Binding alone grants no readiness or remote connectivity receipt.

Termination closes original application, monitor and TRANSPORT streams and
clears session keys and plaintext. Readiness errors reach the same shutdown path.
All foreground exits disconnect the original Resolver and preserve independent
cleanup errors and public counters. `Host::Drop` also performs immediate shutdown
when a whole waiting future is canceled. `STOPPED` reports public counters only.
