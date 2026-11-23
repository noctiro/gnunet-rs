# Configured UDP communicator runtime

This adapter composes the native UDP communicator, PILS identity, NAT
registration, TRANSPORT APPLICATION and the shared Resolver broker. It owns
the sockets, original connections and replay state through bounded retirement.

## Application entry

Call `serve_embedded` on the application's Tokio I/O and time driver. Pass
`EmbeddedSettings` with the UDP configuration, the existing absolute peer key
path, a separate private replay directory and the shared `RuntimeClock`. The
configuration selects local PILS, NAT, TRANSPORT and RESOLVER endpoints.
Choose `HelloPublisher::Transport` when TRANSPORT publishes the aggregate HELLO.
Choose `HelloPublisher::Communicator` only when UDP owns the complete address set.

The readiness callback receives the verified peer and original UDP socket
addresses after the initial registration write on the local TRANSPORT stream.
An already requested stop skips binding. A later stop drives the same bounded
retirement as the [standalone program](../../apps/gnunet-communicator-udp/README.md).
The application supplies its own process identity and UDP socket permissions.
`EmbeddedSettings.socket_policy` prepares each original socket before bind.
The same policy covers discovery sends, replacement burst scan sockets and
healthy identity replacement; ordinary standalone startup uses the default policy.

## Configuration

`[communicator-udp] BINDTO`, `BINDTO6` and `DISABLE_V6` select numeric family
listeners. `DISABLE_BROADCAST`, `REKEY_INTERVAL` and `REKEY_MAX_BYTES` retain
the standard communicator settings. `[communicator-udp-rust] ACK_TIMEOUT`
controls the sender's acknowledgement window. See the [runtime contract](API.md)
for identity, publication, recovery and shutdown.
