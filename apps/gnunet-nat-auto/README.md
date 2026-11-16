# gnunet-nat-auto

Query official GNUnet NAT autoconfiguration and run finite reachability tests
using the shared [NAT caller](../../adapters/nat-test-std/README.md). Linux, macOS,
FreeBSD and Windows use the same command implementation.

## Configuration and examples

Configure `[nat-auto]` for autoconfiguration and `[nat]` plus
`[gnunet-nat-server]` for tests. Services use their configured Unix or TCP endpoint.
The tested adapter section supplies its `PORT`.

```sh
gnunet-nat-auto -c gnunet.conf --auto
gnunet-nat-auto -c gnunet.conf --section transport-udp --udp
gnunet-nat-auto -c gnunet.conf --auto --write
```

`--auto` prints the returned status/type and proposal. `--write` requires
`--auto` and publishes only the successful proposal's NAT values to the selected
configuration. It does not reconfigure a running daemon. Tests require exactly
one of `--tcp` or `--udp`; `PORT = 0` selects reversal testing.

Shared PROGRAM options select configuration, logging, help and version output.
See the [NAT caller reference](../../adapters/nat-test-std/README.md) for limits,
challenge semantics and reversal constraints.

## Results and cancellation

A configuration proposal is not a connectivity result. Reachability requires the
original matching network-path observation, which remains unauthenticated.
Cancellation closes the original query/test owners before Resolver disconnect.
Action, cleanup and selected-Logger failures remain visible in the exit result.
