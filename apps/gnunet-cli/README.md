# gnunet-cli

Commands for GNUnet service IPC and local FS operations.

```sh
cargo build -p gnunet-cli --locked
gnunet-cli --help
```

The [command reference](commands.md) contains examples, configuration selection,
JSON fields and completion/error behavior for STATISTICS, FS, NAMESTORE,
IDENTITY, VPN, REGEX and TRANSPORT.

An explicit socket path selects that service endpoint. Commands supporting `-`
resolve the endpoint from normal configuration. Service commands require a
listening service; local FS/crypto operations use their documented local inputs.

Streaming output may precede a failure. Require exit zero and the command's
terminal completion event. Timeouts, local writes and empty observations are not
remote acknowledgements or not-found results. Mutations with unknown outcomes
are not automatically replayed.
