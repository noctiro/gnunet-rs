# Ordinary CONSENSUS SERVICE

The ordinary installed name and endpoint are gnunet-service-consensus/[consensus].

## Startup and configuration

Configured SERVICE startup, inherited listeners, explicit username before Unix
listener completion, shared selected Logger/Clock/Resolver,
parent control, signals and independent shutdown follow the normal facilities. READY means IPC admission/listeners; it does not claim a live PILS or peer.

The shared [Unix entry](../../adapters/program-std/src/service/native/unix.rs)
owns privilege changes and fork detachment. The shared
[Windows entry](../../adapters/program-std/src/service/native/windows.rs)
owns process-token identity verification, native
listener activation, managed console detachment or standalone re-exec, and
original-parent readiness/control. Both use the same foreground and cleanup
owners. Readiness submission is bounded and retains its first admitted status;
initialization and notification failures remain independent.

Missing `UNIX_MATCH_UID` and `UNIX_MATCH_GID` default to YES on Unix and NO on
Windows. Explicit Unix credential checks remain unsupported on Windows; native
endpoint ACLs and configured process identity use their own platform mechanisms.
Run `gnunet-service-consensus -c service.conf`; `-d` selects native detachment.

## Session ownership

Each original IPC session must own its true PILS Instance/Client, core Instance,
SET Factory and Bridge on its own pinned local future. Actual verified PILS
identity is the local source; no configuration/first peer guesses it. SETI/SETU
are not substituted for old generic SET. Only whole output receipts may
complete original523/525; known source loss fences new IO while original partial
frames retain dispositions. Core first causes and independent physical
retirement remain separate. There is no normal Consensus CLI in active C Meson.

## Resource policy

[consensus-service-rust] selects finite client/session/aggregate reservations,
original first/partial/operation/retirement/shutdown bounds, core pool/phase task/
set/offer/work limits and SET/PILS/HELLO/Resolver resources. SET_BYTE_ORDER
and SET_ALIGN64 explicitly select the SET source profile. Node-wide
`[PILS] PROFILE` selects identity derivation. Optional local PILS_PROFILE
must agree with an explicit node choice. `reference029` is the default;
`deterministic` (also `reference-deterministic`) selects the official conditional
build. Explicit `lsd0014-text` selects the separate published contextual-label
text and does not grant official C build interoperability. No verification
fallback is used. Unknown application labels remain opaque; only their app owner
may claim successful validation. No key, data source or computed result is faked. The process shares4096 bounded clock subscription slots; resource refusal is an
error. Reservations and finite memory profiles are not measured RSS.
