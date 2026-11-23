# gnunet-helper-nat-server

Observe official GNUnet reversal packets using the shared
[native helper implementation](../../adapters/nat-helper-std/).

## Arguments and output

```text
gnunet-helper-nat-server LOCAL_IP
```

The address is numeric IPv4. Stdin carries no commands. Stdout emits only
`IPv4:PORT\n`, or `IPv4\n` for the zero-port diagnostic. These are unauthenticated
observations. Consumers must retain the original child, source and interface
intent and require a complete line; exit zero is not a connectivity receipt.

## Platforms and lifetime

Linux, Android system images, OpenHarmony standard systems, macOS, FreeBSD 12+
and Windows use the same packet algorithms and 500 ms alternating probe
schedule. Output retains one bounded line with its
original cursor and two-second target. Unix checks its original parent and stop
signals after credential dropping. Windows requires a qualified private byte
pipe; the normal Rust NAT supervisor provides it and reader closure ends that
output generation. Windows uses the invoking token's existing raw permissions.
See the host for exact native privilege, pipe and cleanup contracts.
