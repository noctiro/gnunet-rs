# gnunet-service-nat

Native Rust foreground for the official address registration and reversal protocol. The shared
[native host](../../adapters/nat-std/) owns providers, mappings, helpers, Resolver
and clock; the [process composition](../../adapters/nat-std/README.md#native-process-composition)
owns PROGRAM options, activation, selected logging and shutdown.

## Configuration and use

```sh
gnunet-service-nat -c gnunet.conf
```

The Unix and Windows entries capture inherited listeners and original parent
control once. Unix applies configured privileges; Windows verifies the process
token. The corresponding service section selects listeners, ACLs and USERNAME;
`[nat]` selects discovery and traversal providers, and `[nat-rust]` sets finite
resource and timeout policy. Explicit Unix UID/GID checks require Unix.

## Readiness and cleanup

READY establishes local listener ownership. Provider notifications, mappings and
remote connectivity require their own observations. ICMP traversal requires
separately built helpers supported by the platform; the process does not install
them or change their privileges. Shutdown drains original helper waits under
their existing bounds and reports unresolved mapping or process cleanup.
