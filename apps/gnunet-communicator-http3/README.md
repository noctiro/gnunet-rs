# gnunet-communicator-http3

Runs the official HTTP/3 communicator through the shared native PROGRAM,
PILS identity source, TRANSPORT IPC and STATISTICS publisher.

## Usage

```sh
gnunet-communicator-http3 -c gnunet.conf
```

## Configuration and constraints

`[communicator-http3] BINDTO` selects the numeric local endpoint. Optional
`KEY_FILE` and `CERT_FILE` must be configured together. The configured services
must already be running. Standard PROGRAM options select configuration and logs.

See the [host contract](../../adapters/quic-communicator-std/README.md) for
resource limits, TLS/ALPN and identity semantics, native platform requirements
and original-source recovery.
