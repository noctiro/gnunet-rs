# GNUnet for OpenHarmony apps

`libgnunet_node.so` exposes the [Rust node SDK](../sdk/README.md) through
Node-API to Stage-model applications on the OpenHarmony standard system.
`GnNode` owns a single ArkTS `ThreadWorker`.
The worker serializes calls to the original Rust node and joins it during
`close()`.

For a foreground executable managed by the system image, use the
[standard-system recipe](system/README.md) or the
[HiSpark Taurus Linux small-system recipe](system/small-linux/README.md).

## Native build

Use an OpenHarmony Public SDK native component for your build host, CMake,
Ninja, Python 3 and the Rust targets below. The public native build workflow uses the
OpenHarmony 6.1 Public SDK 6.1.0.31 (API 23). [OpenHarmony release downloads](https://github.com/openharmony/docs/blob/master/zh-cn/release-notes/OpenHarmony-v6.1-release.md#从镜像站点获取) · [OpenHarmony Rust targets](https://doc.rust-lang.org/rustc/platform-support/openharmony.html)

| OpenHarmony ABI | Rust target |
| --- | --- |
| `arm64-v8a` | `aarch64-unknown-linux-ohos` |
| `armeabi-v7a` | `armv7-unknown-linux-ohos` |
| `x86_64` | `x86_64-unknown-linux-ohos` |

From the repository root with `OHOS_NATIVE` set to the extracted `native`
directory, install the Rust targets and run the build script.

```sh
rustup target add $(sh platform/openharmony/build-sdk.sh --rust-targets)
sh platform/openharmony/build-sdk.sh
```

Pass ABI names such as `arm64-v8a` to build a subset. The script builds the
Rust archive and links the C++ Node-API module with the same SDK. It stages the
native binaries, ArkTS sources and package metadata as a source HAR module under
`target/openharmony/` and writes its absolute directory to standard output.
Build messages go to standard error. The binary contains a static C++ runtime.
Use the same runtime linking mode across the application's native libraries.
Set `GNUNET_OHOS_BUILD_JOBS` to select build concurrency. [OpenHarmony C++ linking modes](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/napi/build-with-ndk-overview.md)

The [native SDK workflow](../../.github/workflows/openharmony-sdk.yml) verifies
the downloaded or cached archive against the [pinned SDK release](sdk-release.json)
before extraction. The quality gate runs it on Linux for pull requests and
release tags. It also supports manual runs and uploads the linked source module.

## App integration

Place the generated directory at `./gnunet_node` in a Stage-model application
project that targets OpenHarmony 6.1 (API 23). Add
`{ "name": "gnunet_node", "srcPath": "./gnunet_node" }` to `modules` in the
project's `build-profile.json5`. Set the product's
`app.products[].buildOption.strictMode.useNormalizedOHMUrl` to `true` so the
worker URL resolves relative to the packaged `GnNode.ets`. [Hvigor project settings](https://developer.huawei.com/consumer/en/doc/harmonyos-guides/ide-hvigor-build-profile-app/) · [OpenHarmony Worker paths](https://github.com/openharmony/docs/blob/master/en/application-dev/arkts-utils/worker-introduction.md#file-url-rules-in-stage-model)

Add a local dependency in the entry module's `oh-package.json5`.

```json5
{
  "dependencies": {
    "gnunet_node": "file:../gnunet_node"
  }
}
```

Install dependencies with OHPM in the application project. Use the matching
DevEco command-line tools to build a `.har` from the project's root.

```sh
ohpm install --all
hvigorw assembleHar --mode module -p module=gnunet_node@default \
  -p product=default --no-daemon
```

To consume the assembled `.har` in another project, point the entry module's
dependency at the archive and keep normalized OHM URLs enabled.
Select only application ABIs present in the library. The library declares
`ohos.permission.INTERNET`; the app declares `ohos.permission.GET_NETWORK_INFO`
for VPN startup or default-network observation. Build and sign the app's HAP
in its own project for device installation. [HAR libraries](https://github.com/openharmony/docs/blob/master/en/application-dev/quick-start/har-package.md) · [Hvigor build commands](https://developer.huawei.com/consumer/en/doc/HarmonyOS-Guides/ide-command-line-building-app/) · [HAP signing](https://github.com/openharmony/docs/blob/master/en/application-dev/quick-start/hap-package.md)

## Optional trusted bootstrap HELLOs

Supply application-selected official HELLO URL files when packaging.

```sh
GNUNET_BOOTSTRAP_HELLO_DIR=/absolute/trusted-hellos \
  sh platform/openharmony/build-sdk.sh
```

The shared producer stages `src/main/resources/rawfile/gnunet/hellos.list`
and numbered files under `gnunet/hellos` in the source HAR. There are no default
peers or network downloads. The canonical ASCII index lists at most 1024 consecutive
filenames starting at `0000.hello`; each file is at most 65535 bytes and their
total is at most 4 MiB.

Install the trusted module resources before launching the node.

```typescript
import { GnNode, IncludedHellos } from 'gnunet_node';

const bootstrapDataDir = await IncludedHellos.install(context.resourceManager, context.filesDir);
const node = await GnNode.launch({
  stateDir,
  ipcDir,
  bootstrapDataDir,
  tcpBind: '127.0.0.1:0',
  udp4Bind: '127.0.0.1:0',
  startupTimeoutMs: 15000,
  drainTimeoutMs: 5000
});
```

The installer uses the public resource manager and asynchronous FileIO APIs.
It writes a fresh app-private generation and returns its absolute data root
only after all listed bodies complete. An incomplete write or sync/close error
fails installation; cleanup failures remain in the diagnostic. Keep a returned
generation unchanged until every node using it has closed, then remove it when
the app no longer needs it. Later installations leave earlier generations
intact. [Raw module resources](https://github.com/openharmony/docs/blob/master/en/application-dev/reference/apis-localization-kit/js-apis-resource-manager.md#getrawfilecontent9-1) · [FileIO operations](https://github.com/openharmony/docs/blob/master/en/application-dev/reference/apis-core-file-kit/js-apis-file-fs.md)

`bootstrapDataDir` is optional and preserves `configFile`. The shared Rust
startup selects the official PEERSTORE import and performs canonical signature,
expiry and public-record checks; see the [SDK contract](../sdk/README.md).

## Lifecycle

Pass existing app-private state and IPC directories. The IPC directory must be
short enough for native Unix socket names. Set `configFile` to an optional
absolute GNUnet configuration path, including optional
[QUIC and HTTP/3 listeners](../sdk/README.md#inputs-and-capabilities). `dnsServers` accepts space-separated numeric
IP addresses or IP:port endpoints. A zero listener port asks the OS for a port.

```typescript
import { GnNode, NodePhase } from 'gnunet_node';

const node = await GnNode.launch({
  stateDir,
  ipcDir,
  tcpBind: '127.0.0.1:0',
  udp4Bind: '127.0.0.1:0',
  startupTimeoutMs: 15000,
  drainTimeoutMs: 5000
});

const snapshot = await node.snapshot();
if (snapshot.phase === NodePhase.Ready) {
  console.info(`GNUnet TCP ${snapshot.tcpPort} and UDP ${snapshot.udp4Port}`);
}
```

`launch()` returns after native startup is scheduled. Use `snapshot()` to
observe readiness, the peer identity, port assignments and a terminal failure.
Use `notifyNetworkChange()` from an application network callback to request
an address rescan.
Use `requestStop()` to keep observing retirement, then `await node.close()` to
release the original node and worker. An ability or application owner retains
this handle and requests close at the end of its chosen lifetime. The native
lifecycle binding is synchronous and belongs on the worker.

## VPN extension resource ownership

`GnNode.launchVpn()` runs the descriptor provider in a dedicated
`VpnExtensionAbility` process on API 22 and later. Retain the node at extension
scope and close it before returning the extension's resources.

```typescript
import { GnNode } from 'gnunet_node';

const node = await GnNode.launchVpn(options, context, {
  routeInterface,
  maximumPacket: 1500
});
await node.close();
```

The app owns extension consent and process isolation. The SDK reserves the
process and awaits `protectProcessNet()` before native startup. Native VPN
starts are exclusive. The process stays dedicated to this profile after
retirement because the framework supplies no process-unbind receipt.
[Official process protection](https://github.com/openharmony/docs/blob/master/en/application-dev/reference/apis-network-kit/js-apis-net-vpnExtension.md#protectprocessnet22)

VPN startup also owns one system-default network observer. By default it sends
native address-rescan hints and keeps application-selected DNS endpoints. To use
OS DNS, pass `upstreamNetwork: { allowUnencryptedDns: true, onError }` in
`VpnNodeOptions`. This explicit permission must cover the application's encrypted
or private DNS policy; the public connection properties provide no such status.
Automatic DNS starts with an empty Resolver list, then replaces it only from a
qualified physical-network snapshot. `dnsAddresses` still configures the VPN
interface's DNS settings. The observer never changes the protected process's
network binding. Automatic DNS is the sole DNS authority for that node;
`setDnsServers()` rejects while it is attached. The default path-only mode keeps
manual DNS updates available.

Use the VPN interface name for your deployment and an explicit
`maximumPacket` in the platform's 576–1500 byte range. The Worker forwards
the configured GNUnet address, route and MTU for each enabled family, with
any explicit `dnsAddresses`. Rust duplicates the public nonblocking vNIC
descriptor from the original successful `VpnConnection.create()`. The
framework retains the original descriptor. The Worker carries only
configuration and completion messages. [Official VPN settings and descriptor](https://github.com/openharmony/docs/blob/master/en/application-dev/reference/apis-network-kit/js-apis-net-vpnExtension.md#vpnconnection)

`close()` requests native retirement, services its original removal command,
waits for `VpnConnection.destroy()` to confirm absence, and joins the Worker.
A failed destroy leaves the process reserved. Await explicit close while the
extension lifecycle permits. The void `onDestroy()` callback can initiate
cleanup. [Extension lifecycle](https://github.com/openharmony/docs/blob/master/en/application-dev/reference/apis-network-kit/js-apis-VpnExtensionAbility.md)

## Live DNS and default-network ownership

`await node.setDnsServers(['192.0.2.53:53', '[fe80::53%4]:53'])` replaces the
upstreams of a starting or ready node without replacing its owner.
`await node.setDnsServers([])` clears them. The list contains at most 32 numeric
IP addresses or IP:port endpoints, with numeric IPv6 scopes. The Worker keeps
one DNS command in flight and one latest snapshot, including an empty
revocation. DNS and stop commands have their own bounded admission slots so an
ordinary request queue at capacity cannot discard them. A completed call means
the Rust owner accepted the update; pending updates can coalesce. Each accepted
update also requests an address rescan.

An application can opt into the system default-network observer:

```typescript
await node.followDefaultNetwork({
  allowUnencryptedDns: true,
  onError: (error: Error): void => { console.error(error.message); }
});
```

This observer requires `ohos.permission.GET_NETWORK_INFO`. Passing
`allowUnencryptedDns: false` observes path changes while preserving explicit DNS.
It owns one `NetConnection` registration shared with VPN startup, unregisters on
stop, close or Worker failure, and records failures for `snapshot()` and `close()`.
An update failure requests stop and reaches `onError`. Close waits for the
original OS read and unregister results as well as the Rust worker join.
The consuming application declares the permission; the SDK does not grant it.
OS permission or registration refusals are surfaced and stop the original node.
[OpenHarmony network connection API](https://github.com/openharmony/docs/blob/master/en/application-dev/reference/apis-network-kit/js-apis-net-connection.md#netconnection)

Callbacks act as coalesced wake hints. One serialized reader obtains
`getDefaultNet()`, reads that exact handle's properties and confirms the current
default and observer generation before publishing DNS. The documented system
default excludes VPN and is independent of application network binding. A
handoff or loss first revokes the old automatic DNS list. A late query, replaced
network or callback after close cannot publish a snapshot. The observer does not
read DNS from callback payloads or activate a selected bearer network.
[System default network contract](https://github.com/openharmony/docs/blob/master/en/application-dev/reference/apis-network-kit/js-apis-net-connection.md#connectiongetdefaultnet)

Only explicit permission enables ordinary DNS queries to OS endpoints. The
public `ConnectionProperties` API has no encrypted-DNS policy field. Without
that permission, supply policy-qualified endpoints with `setDnsServers()`.
Automatic snapshots are bounded to 32 servers and 4096 ASCII bytes. Explicit
numeric IPv6 scopes are preserved. For unscoped link-local DNS, the qualified
snapshot's `interfaceName` is resolved with native `if_nametoindex()`, once per
snapshot when needed. Missing interfaces omit that endpoint; native lookup
failure is reported. Names must fit `IF_NAMESIZE` without truncation or NUL.
Automatic DNS rejects manual updates; path-only observation permits them.
[Address properties](https://github.com/openharmony/docs/blob/master/en/application-dev/reference/apis-network-kit/js-apis-net-connection.md#connectionproperties) ·
[Native interface lookup restrictions](https://github.com/openharmony/docs/blob/master/en/application-dev/reference/native-lib/guidance-on-ndk-libc-interfaces-affected-by-permissions.md#common-selinux-affected-interfaces)
