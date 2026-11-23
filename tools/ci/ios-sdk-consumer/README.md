# iOS SDK consumer

The Xcode `Consumer` scheme links the generated `GNUnetNode` package into an
iOS app and its Packet Tunnel and DNS Proxy app extensions. Both extensions
enable extension-safe API checking. The app and Packet Tunnel target iOS 15
and later. The DNS Proxy targets iOS 18 and later.

## Build the app and extensions

Build the [iOS Swift package](../../../platform/ios/README.md#build-and-import).
From the repository root, set `package` to the absolute path printed by
`platform/ios/build-sdk.sh`:

```sh
consumer=$(mktemp -d "$PWD/target/ios/consumer.XXXXXXXX")
cp -R tools/ci/ios-sdk-consumer/. "$consumer/"
ln -s "$package" "$consumer/GNUnetNode"
xcodebuild -project "$consumer/Consumer.xcodeproj" -scheme Consumer \
  -destination 'generic/platform=iOS' -derivedDataPath "$consumer/build" \
  -jobs 1 CODE_SIGNING_ALLOWED=NO build
```

The build embeds `TunnelProvider.appex` and `DnsProxyProvider.appex` under
`Build/Products/Debug-iphoneos/Consumer.app/PlugIns/` in the derived data
directory. Use `generic/platform=iOS Simulator` for the simulator library slice.
The unsigned build checks app packaging and linkage without developer credentials.

## Packet Tunnel deployment

Use a team with the Packet Tunnel capability and provisioning profiles for both
bundle identifiers. The extension identifier uses the containing application's
identifier as its prefix. The VPN configuration comes from the host application
or managed deployment. Its `NETunnelProviderProtocol` selects the extension
identifier and supplies the server address as NetworkExtension metadata.
[Apple extension setup](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider) ·
[Apple deployment profiles](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)

The fixture's `providerConfiguration` accepts:

| Key | Value |
| --- | --- |
| `upstreamInterface` | Required. `wifi`, `wiredEthernet` or `cellular`. |
| `upstreamDnsServers` | Optional numeric DNS endpoints for GNUnet on the qualified path. |
| `tunnelDnsServers` | Optional numeric DNS addresses for NetworkExtension settings. |
| `ipv4ExcludedRoutes`, `ipv6ExcludedRoutes` | Optional arrays of numeric CIDR prefixes chosen by the deployment. |
| `configurationFile`, `bootstrapDataDirectory` | Optional absolute paths readable inside the extension's sandbox. |

The provider admits only a satisfied path with the requested interface type.
The deployment establishes the original outbound routes and keeps them outside
the GNUnet tunnel prefixes, including after path changes. Qualify routing,
signed installation and native resource retirement on the target device.
[Packet tunnel lifecycle](../../../platform/ios/README.md#packet-tunnel-node)

## DNS Proxy deployment

Sign the containing app and both extensions. The DNS Proxy extension's
provisioning profile must authorize the `dns-proxy` Network Extension entitlement.
Use the supervised device profile for device-wide DNS or an MDM per-app
profile whose `DNSProxyUUID` matches the targeted managed apps. Set
`AppBundleIdentifier` to `org.gnunet.sdk.link-probe` and
`ProviderBundleIdentifier` to `org.gnunet.sdk.link-probe.dns-proxy`.
Supply `GNUNET_CONFIG` through `ProviderConfiguration`.
[SDK configuration](../../../platform/ios/README.md#dns-proxy-provider) ·
[Apple deployment profiles](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment#Deploying-a-DNS-proxy-provider) ·
[Apple DNS Proxy payload](https://support.apple.com/guide/deployment/dns-proxy-payload-settings-dep500f65271/web)
