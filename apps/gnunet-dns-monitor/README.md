# gnunet-dns-monitor

Display DNS interception callbacks and forward them unchanged. The native
PROGRAM entry uses shared configuration, logging and parent/stop control.

## Usage

```sh
gnunet-dns-monitor -c node.conf --duration-ms 30000
```

See [DNS tools](../../adapters/dns-tools-std/README.md) for options, endpoint
selection, resource limits and shutdown behavior. A DNS interception service
must already be running.
