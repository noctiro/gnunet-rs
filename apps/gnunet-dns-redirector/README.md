# gnunet-dns-redirector

Replace answer-section A/AAAA addresses received from the DNS interception
service. The native PROGRAM entry shares configuration and lifecycle handling.

## Usage

```sh
gnunet-dns-redirector -c node.conf --ipv4 192.0.2.10
```

See [DNS tools](../../adapters/dns-tools-std/README.md) for options, exact packet
preservation, endpoint selection and resource limits. A DNS interception service
must already be running.
