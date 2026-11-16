# gnunet-nat

Monitor official GNUnet NAT registration, STUN observations and reversal callbacks
using the native [NAT client](../../adapters/nat-test-std/README.md). The same
command implementation supports Linux, macOS, FreeBSD and Windows.

## Configuration and examples

The selected configuration supplies `[nat] UNIXPATH` or its TCP service endpoint.
The section named by `--section` identifies the adapter registration.

```sh
gnunet-nat -c gnunet.conf --section transport-udp --in 127.0.0.1:2086 --udp
gnunet-nat -c gnunet.conf --section transport-udp --in 127.0.0.1:2086 --udp --stun
```

Use `--remote` for one reversal request and `--watch` to print reversal callbacks.
`--tcp` and `--udp` are mutually exclusive; `--stun` requires UDP. Shared PROGRAM
options select configuration, logging, help and version output. See the linked
[NAT command reference](../../adapters/nat-test-std/README.md#commands-and-configuration)
for lifetime and STUN configuration.

## Results and cancellation

Address hints, local writes and matching public challenges are separate results.
None authenticates a peer. Reconnect creates a fresh registration lease and does
not replay the original reversal request. Native stop closes the original owners;
Resolver and selected-Logger errors affect the command result.
