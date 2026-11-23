# macOS DNS system extension

`gnunet-dns-proxy` is the OS-launched macOS 15+ DNS provider entry point. Its
`GNUnetDNSProxyProvider` class delivers original UDP flows to the existing
GNUnet DNS service and TCP flows to a bounded byte relay. Official client IPC,
PRE/POST processing, configuration and foreground cleanup remain shared with
[gnunet-service-dns](../README.md).

## Assemble the bundle

Build on macOS, then assemble a new unsigned bundle:

```sh
cargo build --release -p gnunet-service-dns \
  --features macos-dns-proxy --bin gnunet-dns-proxy

cargo xtask bundle-dns-proxy \
  --binary target/release/gnunet-dns-proxy \
  --output target/package/org.example.gnunet.dns-proxy.systemextension \
  --bundle-id org.example.gnunet.dns-proxy \
  --app-group ABCDE12345.org.example.gnunet \
  --version 1.0.0
```

Replace the example identifiers with those provisioned for the distribution.
`--app-group` is the full string present in the signed application-group
entitlement; the helper adds no team prefix. `--version` accepts three numeric
components and defaults to `1.0.0`. The output basename must equal
`<bundle-id>.systemextension`. Existing bundles and entitlements are not replaced;
an error after creation leaves the partial artifact for inspection.

The helper validates the input's Mach-O/universal executable headers and copies
it without execution. It writes:

| Path | Content |
| --- | --- |
| `Contents/MacOS/gnunet-dns-proxy` | Supplied executable. |
| `Contents/Info.plist` | System-extension metadata and native provider-class map. |
| `Contents/Resources/share/gnunet/config.d/` | Directory for explicit installation defaults. |
| Adjacent `<bundle-id>.entitlements` | Signing input, outside the extension bundle. |

Populate the defaults directory with the installation configuration required by
your deployment before signing. The helper does not copy a machine's GNUnet
configuration, sign the result or activate it.
The [Info.plist template](Provider-Info.plist.in) maps
`com.apple.networkextension.dns-proxy` to the exact Rust runtime class name
`GNUnetDNSProxyProvider`. The [entitlements template](Provider.entitlements.in)
requests `dns-proxy-systemextension` and the supplied application group.
The Info template also provides `NSSystemExtensionUsageDescription`, which Apple
requires for non-DriverKit system extensions.
[Usage description requirement](https://developer.apple.com/documentation/systemextensions/nssystemextensionusagedescriptionkey)

`NEMachServiceName` is `<app-group>.dns-proxy.<version>`. Apple DTS explains that
the entitled app group must prefix this name. A separate DTS reply suggests a
per-version name as an upgrade/XPC workaround; this is not an activation or
upgrade guarantee.
[App-group mapping](https://developer.apple.com/forums/thread/776759),
[versioned-name discussion](https://developer.apple.com/forums/thread/779395)

## Containing application

`gnunet-dns-control` hosts explicit management commands in a real main-thread
AppKit application loop. Build both executables and assemble a new unsigned app:

```sh
cargo build --release -p gnunet-service-dns --features macos-dns-proxy \
  --bin gnunet-dns-proxy
cargo build --release -p gnunet-service-dns --features macos-dns-control \
  --bin gnunet-dns-control

cargo xtask bundle-dns-app \
  --control-binary target/release/gnunet-dns-control \
  --provider-binary target/release/gnunet-dns-proxy \
  --output 'target/package/GNUnet DNS.app' \
  --bundle-id org.example.gnunet \
  --provider-id org.example.gnunet.dns-proxy \
  --app-group ABCDE12345.org.example.gnunet \
  --version 1.0.0
```

The provider identifier must be a child of the application identifier. The app
contains the control executable and embeds the provider under
`Contents/Library/SystemExtensions/<provider-id>.systemextension`. Application
and provider signing inputs are adjacent to the app, outside both bundles.
The generated application metadata binds control to that provider identifier
and version. Both executables use checked copies of the supplied Mach-O files;
the helper executes neither file, signs nothing and refuses existing outputs.
Build the two binaries separately as shown: the provider feature excludes
AppKit and SystemExtensions management code, while the control feature enables
that containing-application boundary.

Use provisioned identifiers and matching signed team identities. Before signing,
populate the embedded provider's defaults and supply the appropriate application
and extension provisioning profiles. Sign the embedded extension and then the
containing application with their respective entitlements. Distribution and
activation remain subject to Apple's deployment requirements and user policy.
The app requests system-extension installation, DNS proxy management and the
shared application group. These templates are signing inputs, not granted
entitlements.
[Installation entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.system-extension.install),
[network-extension entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)

## Stage and activate a signed application

On macOS, include the signed containing app when staging a matching node.

```sh
cargo xtask stage-node --jobs 1 --output target/gnunet-node \
  --macos-dns-app 'target/package/GNUnet DNS.app'
```

Both executables must contain the node's x86_64 or arm64 slice. Staging checks
all supplied slices, the outer and embedded code signatures, the matching
team, the declared provider ID and version, and the signed entitlements for the
shared application group. The input may contain up to 4096 ordinary files and
directories, 1 GiB total and 24 levels of nesting.

The result appears under `share/gnunet/providers/macos` with its input app name,
preserved bundle metadata and matching code directory hashes. Copy the whole app
into `/Applications` under the distribution's installation policy, then run the
signed control executable from that location. It starts the AppKit event loop
and submits the original system-extension and DNS preference requests.
[Apple deployment requirements](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment) ·
[Apple DTS application requirement](https://developer.apple.com/forums/thread/776759)

```sh
'/Applications/GNUnet DNS.app/Contents/MacOS/gnunet-dns-control' status
'/Applications/GNUnet DNS.app/Contents/MacOS/gnunet-dns-control' \
  enable --config /absolute/path/node.conf
'/Applications/GNUnet DNS.app/Contents/MacOS/gnunet-dns-control' disable
'/Applications/GNUnet DNS.app/Contents/MacOS/gnunet-dns-control' remove
```

| Command | Native sequence |
| --- | --- |
| `status` | Load and show this application's saved DNS preferences. |
| `enable --config PATH` | Validate shared provider configuration, request extension activation, then load and save the owned DNS configuration enabled. Reload and check the saved state. |
| `disable` | Load the owned configuration, save it disabled without replacing vendor fields, then reload and check. |
| `remove` | Load and remove the owned configuration, then request extension deactivation. |

`enable` requires an absolute UTF-8 configuration filename. It completes the
extension request before submitting an enabled preference save. A result
requiring reboot stops that sequence. `--replace` permits only a strictly newer
same-bundle/team extension with this app's exact packaged version; default
activation refuses replacement conflicts. Enabling a DNS proxy can disable
another application's proxy under the native manager's contract.

Every preference mutation requires a successful load and an exact provider
identity match. Malformed owned `GNUNET_CONFIG` values remain visible as errors;
they do not prevent explicit disable/removal. Status reports persisted settings,
not installed-extension properties, provider health or DNS delivery.

`--timeout SECONDS` bounds the native command wait, defaults to 120 and accepts
1–3600. Expiry or application exit does not cancel a submitted native effect.
Pending extension requests retain bounded request/delegate loans through their
terminal callback and deferred disposal; preference callbacks keep their unique
manager reservation until actual disposal. Approval and reboot requirements,
save completion and provider readiness remain separate outcomes.

## Configuration

The containing application's `NEDNSProxyProviderProtocol.providerConfiguration`
must include `GNUNET_CONFIG` with a complete, readable absolute filename. Apple
passes that dictionary to the provider's startup options.
[Provider configuration contract](https://developer.apple.com/documentation/networkextension/nednsproxyproviderprotocol/providerconfiguration)

The provider derives its installation prefix from `Contents/Resources` and loads
`share/gnunet/config.d` before the explicit file. It does not change environment
variables in its multithreaded process. macOS supplies process identity; a
nonempty effective `[dns] USER` is refused. Listener paths, ACLs and access to
other GNUnet services must suit that identity. The normal service CLI retains
its existing configuration and identity behavior.

The usual `[dns]` listeners and numeric `DNS_EXIT` configure the shared service.
Provider UDP/TCP traffic uses Network.framework; no helper/TUN interface or PF
policy is installed by this entry point. These additional `[dns-rust]` settings
control native bounds:

| Setting | Default | Meaning |
| --- | --- | --- |
| `NATIVE_FLOWS` | `32` | UDP flows, including closing callback owners. |
| `NATIVE_BATCH_DATAGRAMS` | `16` | Copied datagrams per UDP read. |
| `NATIVE_BATCH_BYTES` | `128 KiB` | Retained DNS allocation capacity per UDP batch. |
| `NATIVE_OPEN_TIMEOUT` | `5 s` | UDP flow opening; TCP flow/upstream opening; each upstream UDP readiness interval. |
| `NATIVE_UPSTREAM_SEND_TIMEOUT` | `30 s` | Fixed submitted upstream UDP send deadline. |
| `NATIVE_MULTICAST_RELAY` | `NO` | Forward ordinary UDP DNS queries to their original multicast destination on port 53. |
| `NATIVE_TCP_FLOWS` | `32` | TCP relays, including closing owners. |
| `NATIVE_TCP_CHUNK_BYTES` | `64 KiB` | Retained TCP chunk bound in either direction. |
| `NATIVE_TCP_WRITE_TIMEOUT` | `30 s` | Fixed write/half-close deadline. |
| `NATIVE_TCP_IDLE_TIMEOUT` | `5 min` | TCP interval without observed byte/EOF activity. |

`DNS_BYTES` retains the shared 65519-byte DNS IPC ceiling. TCP does not enter the
UDP DNS phases or acquire that datagram framing. The SDK TCP read API has no
maximum-length parameter: a callback exceeding the reserved chunk fails rather
than truncating the stream. Native SDK allocations are separate from the Rust
buffer limits.

With `NATIVE_MULTICAST_RELAY = YES`, a port 53 group query uses one native
exchange on the original bound interface and local endpoint. The provider
returns the first matching reply from its actual unicast sender. The hard
deadline is `REQUEST_HARD_LIFETIME`, measured from the original native read.
This explicit original-destination relay runs outside the GNUnet PRE/POST
pipeline. The default unicast path continues to use that pipeline. Port 5353
mDNS and other multicast destination ports are outside this relay profile.
Native delivery and recursion qualification are tracked in
[implementation status](../../../IMPLEMENTATION_STATUS.md).

## Deployment and acceptance

Use the signed distribution's provisioning, installation and approval policy
for native qualification. macOS launches the system extension after the
containing application's activation request.

Startup completes after the shared listeners, gateway and sources exist. Stop
closes admission, drains original flow and upstream callbacks and then fulfils
the original OS completion. Native write acceptance remains distinct from
application consumption. Compilation and ordinary loopback tests do not prove
signed-provider startup, upstream recursion exclusion or original-zone delivery;
see [native qualification](../../../adapters/dns-service-std/NATIVE_BACKENDS.md#qualification).
