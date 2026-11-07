# Ordinary RPS command

`gnunet-rps` uses the official RPS native SDK and ordinary selected
PROGRAM configuration. It creates no service or separate worker. Default mode
requests one random public peer; optional positional `N` requests that many.

- `-s/--seed PEER_ID`: require the full52-character Crockford public identity,
  send one standard seed frame, then print `Seed submitted: <PEER_ID>`.
  This is an local whole write, with no service processing ACK.
- `-V/--view [N]`: observe view batches. Omitted or zero N is continuous;
  positive N completes only after exactly that many SDK frames and output flushes.
- `-S/--stream`: observe biased input batches. Its help identifies the biased
  input; ordinary stdout remains PeerID lines.

Exactly one mode is selected. Sampling retains all N shared-core sampler
results from the same original source before admitting one complete stdout
result. There is no partial sampler result printed as a completed N request. Nonempty sample, View and raw Stream stdout consists only of full public peer
identities, one per line, matching ordinary C command pipeline consumption. Empty
View prints `Empty view`; empty Stream prints `No peer was returned`. Source
epochs, batch counters and byte counts are retained internally for guards and
diagnostics without entering data stdout. No fake wire END, request ID, seed acceptance or remote receipt is introduced.

The command uses one SharedClock, selected Logger/Reporter, live selected
configuration and shared Resolver through the prepared PROGRAM scheduler. Ctrl-C/SIGTERM closes its source and Resolver; parent PROGRAM cancellation
also physically closes the retained native owner and records cleanup facts. A canceled finite request fails rather than claiming a full sample/quota. Continuous mode can stop cleanly on a signal only with no incomplete stdout
result. EOF, source failure, expired original bounds, logging, Resolver and
stdout errors remain failures. No automatic cross-epoch sample/replay exists.

Local resource policy is read from `[rps-client-rust]`:

| Key | Default |
| --- | --- |
| `TOTAL_TIMEOUT` | 60 seconds, or3600 seconds for continuous mode |
| `INITIAL_TIMEOUT` | 30 seconds |
| `INPUT_TIMEOUT` | 10 seconds for an original partial input frame |
| `OUTPUT_TIMEOUT` | 10 seconds per original admitted stdout result |
| `MAX_FRAME_BYTES` | 65535 |
| `IO_SLICE_BYTES` | 65535 |
| `MAX_SAMPLE_PEERS` | 1024, maximum65536 |
| `MAX_OUTPUT_BYTES` | 4 MiB, maximum16 MiB |
| `REPLY_COUNT_PROFILE` | `native`, or explicit `little`/`big` target C ABI |

These finite local policies do not alter public message fields or renew the
original native/canonical command targets. The service endpoint comes from the
ordinary `[rps]` configuration. No subgroup CLI option is invented; the native
SDK separately supports same-MQ subgroup operation.

Stdout retains one bounded result and offers at most512 bytes per turn. Positive
progress is driven immediately; WouldBlock uses a finite10 ms cadence while the
original source guard, signals, selected Logger and shared Resolver remain
polled. Deadline checks occur before and after writes and flush. A synchronous
OS/stdio/entropy/crypto call cannot be preempted, and a late return fails even
when bytes have escaped. On failure, output prefix/flush causes and original
source retirement/Resolver cleanup stay independent. Shutdown does no extra
stdout IO after its original failure decision.
