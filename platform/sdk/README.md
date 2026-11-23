# GNUnet node SDK

The [C ABI](include/gnunet_node.h) gives Android, iOS and OpenHarmony
applications one Rust node worker. It runs the same
[embedded peer](../../adapters/node-std/README.md) as Rust callers.

## Inputs and capabilities

Supply existing private state and IPC directories, numeric TCP and UDP binds,
and two positive timeouts. The IPC path must fit the operating system's Unix
socket address. An optional absolute configuration file supplies the ordinary
GNUnet settings. An optional DNS list supplies at most 32 numeric endpoints in
preference order. Inputs are copied during `gnunet_node_start`.

To use packaged HELLOs, install the assets in a stable filesystem data
directory and supply its absolute path as `bootstrap_data_dir`. The
[PEERSTORE importer](../../adapters/node-std/README.md#configuration-and-lifecycle)
reads the `hellos` child. The SDK options and original configuration file
remain separate inputs.

Enable raw QUIC or HTTP/3 through `BINDTO` under the corresponding section in
the configuration file. Each profile binds a separate UDP socket.

```ini
[communicator-quic]
BINDTO = 127.0.0.1:0

[communicator-http3]
BINDTO = 127.0.0.1:0
```

`gnunet_node_start` returns the worker handle. `gnunet_node_snapshot` reports
the original local readiness identity and bound ports. An optional port or
`unix_mtu` of zero means the corresponding communicator is disabled.
On Unix hosts, configure [private UNIX datagrams](../../adapters/node-std/README.md#configuration-and-lifecycle)
through `[communicator-unix]` and `UNIXPATH`. `has_ready` retains the ready
snapshot through shutdown. A failed worker exposes an immutable UTF-8
diagnostic of up to 4096 bytes through `gnunet_node_error`.

Call `gnunet_node_notify_network_change` from a host network callback to request
an address rescan on the starting or running worker. When the host also knows
the DNS servers for the current network, call `gnunet_node_set_dns_servers`
with the full list. This also requests a rescan. An empty list removes all
upstreams. Pending snapshots can coalesce and a new network may reuse the same
DNS addresses.

## Application VPN

`gnunet_node_start_with_vpn` transfers an original node and a VPN control
handle. Run the controller on an application worker while waiting for node
readiness and during shutdown. Each configuration or packet command carries
its original token. Complete route commands after the operating system
finishes the exact install or removal. In descriptor mode, report successful
installation with `gnunet_vpn_install_descriptor`. The SDK makes a
close-on-exec duplicate during that call and retires it before the application
removes the platform interface. Application packet mode exchanges bounded
whole raw IP packets while retaining the same route and write receipts.

Internet redirects use official REGEX exit discovery through the embedded
node. Specify `[vpn-rust] EXIT_DISCOVERY=configured` when supplying fixed
gateways in `CONFIGURED_EXITS`.
[Exit policy](../../apps/gnunet-service-vpn/CONFIGURATION.md#exit-discovery)

Set the peer mode to outbound TCP and leave bind strings empty to dial peers
without a peer-facing listener. Establish upstream detour routing before
invoking `gnunet_node_start_with_vpn`.
When the deployment protects individual Unix sockets, use
`gnunet_node_start_with_protected_vpn`. The supplied callback borrows each
original Internet descriptor before it can be bound or used for traffic. A
valid context transfers at startup and is released after its last owner exits.
On permission loss, call `gnunet_vpn_fence` to stop packet admission before
requesting node stop. Drive the controller through actual native route
retirement, then join the node and release the original controller.
[C interface](include/gnunet_node.h)

## Ownership and deployment

Keep one owner for each handle. `gnunet_node_stop` is idempotent. Query the
original worker until it stops or fails, then consume the handle with
`gnunet_node_destroy`. Destruction also requests stop and joins the worker,
so run it on a background queue and exclude other accesses to that handle.

Build the static archive using the target's SDK toolchain.

```sh
cargo build --locked --release -p gnunet-node-sdk --target TRIPLE
```

The archive is named `libgnunet_node_sdk.a` on Unix targets. See the integrations for
[Android](../android/README.md), [iOS](../ios/README.md) and
[OpenHarmony](../openharmony/README.md).

The SDK build scripts stage the project license, [source notices](../../NOTICE.md)
and `THIRD_PARTY_LICENSES.txt` for the Cargo runtime dependencies of all packaged
slices. To package an archive manually, collect the same files with:

```sh
cargo xtask stage-sdk-licenses --output target/sdk-notices --target TRIPLE
```

Repeat `--target` for each packaged slice. Keep those notices with the SDK.
Supply separate notices for non-Cargo libraries or toolchain components that
your SDK redistributes.
