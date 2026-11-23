# Android node SDK

The Android application library exposes one Rust GNUnet node through
`org.gnunet.sdk.GnunetNode`. It targets Android API 24 and later and relies on
the host's application and networking APIs. The JNI shared library links the
Rust archive for the selected ABI using the [common SDK header](../sdk/include/gnunet_node.h).
For an init-managed native node in a vendor image, see the
[Android system integration](system/README.md).

## Android library build

Use the [AAR build script](tools/README.md) to build the Rust archive, JNI
library and Kotlin API for the ABIs in the [SDK profile](sdk-profile.properties).
The all-ABI build currently stops at the
[Android x86 SDK dependency limit](../../IMPLEMENTATION_STATUS.md#known-limits).

```sh
bash platform/android/tools/build-sdk.sh --rust-targets
bash platform/android/tools/build-sdk.sh
```

## Add the SDK to an app

Extract `target/android-sdk/gnunet-node-android-maven.zip`. Add the extracted
`maven` directory to the app's dependency repositories in
`settings.gradle.kts`, alongside its existing repositories.

```kotlin
maven {
    url = uri("third-party/gnunet/maven")
    content { includeModule("io.github.noctiro", "gnunet-node-android") }
}
```

In the app module, use the Maven coordinate in the generated `artifact.json`.

```kotlin
dependencies {
    implementation("io.github.noctiro:gnunet-node-android:0.1.0")
}
```

Gradle resolves the SDK's Kotlin runtime dependency through the Maven
metadata. Apps importing the flat `gnunet-node-android.aar` manage that
dependency themselves.
[Android library dependencies](https://developer.android.com/studio/projects/android-library#UseLibraryInOtherProjects)

## Application ownership

Start and close the node on a background thread. An app using Kotlin coroutines
can use `Dispatchers.IO` for both calls.

```kotlin
val node = withContext(Dispatchers.IO) {
    GnunetNode.start(applicationContext)
}

// Retain node in the application owner and inspect node.snapshot() as needed.
node.requestStop()
withContext(Dispatchers.IO) { node.close() }
```

`start(Context, configFile)` takes an optional GNUnet configuration file and
creates private state and IPC directories under `noBackupFilesDir`, so Android
backups omit the peer key. It owns one default
network callback until `requestStop()` or `close()`. A handoff or loss clears
the old upstreams before the new network's `LinkProperties` supplies its DNS
addresses. Callback data is matched to its original `Network`; late callbacks
and reads cannot restore a retired network's DNS. API 24–25 use one background
reader with one pending snapshot because ordered initial link-property
callbacks are guaranteed only from API 26. The reader checks the default
network before and after its read. [Android network callbacks](https://developer.android.com/develop/connectivity/network-ops/reading-network-state)

The observer clears upstreams while Android Private DNS is active or strict. IPv6 DNS
endpoints retain their numeric scope; an unscoped link-local endpoint is used
only when the corresponding link's interface index can be obtained.
[Private DNS properties](https://developer.android.com/reference/android/net/LinkProperties#isPrivateDnsActive())

## Bootstrap HELLOs

On a background thread, call `AndroidNodeOptions.installIncludedHellos(context)`
to install the app's packaged HELLO files under `noBackupFilesDir`. Pass the
returned directory as `bootstrapDataDirectory` to `GnunetNode.start`. Reuse
the directory for subsequent starts. Installation publishes each complete asset
version atomically. The same verified files reuse their directory, and an update
keeps older directories available to existing owners. The existing `configFile`
can still supply other node settings. Rust verifies the original HELLOs under the
configured profile.

For AAR packaging, set `GNUNET_BOOTSTRAP_HELLO_DIR` to a local directory of
known HELLO files. Apps can also prepare the same `gnunet/hellos` and
`gnunet/hellos.list` layout in their own assets with the shared [asset builder](../../tools/ci/stage-bootstrap-hellos.sh).
The default AAR contains no bootstrap files. When supplying an already installed
filesystem data directory, set `Options.bootstrapDataDirectory`.

## Node status and DNS policy

Use `start(Options)` for application-managed paths, numeric binds, configuration
or DNS policy. `AndroidNodeOptions.fromContext()` remains a one-time options
snapshot. Call `node.setDnsServers(listOf("192.0.2.53:53", "[fe80::53%4]:53"))`
to replace at most 32 numeric upstreams on a starting or ready node;
`setDnsServers(emptyList())` clears them. Updates are copied atomically and
coalesced, and also request an address rescan. Supply only endpoints permitted
by the application's DNS policy. With the owned default observer, subsequent
link callbacks replace explicit updates. `notifyNetworkChange()` requests only
a local address rescan. Default listener binds are loopback; select reachable
interfaces explicitly for peer-facing traffic.

Keep the owner open while observing startup and stop. A `READY` snapshot
carries the verified peer and bound communicator ports. The configuration file
controls optional [QUIC and HTTP/3 listeners](../sdk/README.md#inputs-and-capabilities).
A `FAILED` snapshot
carries the native diagnostic. `requestStop` is idempotent, and `close` joins
the original worker. Observer failures request stop and appear separately in
`Snapshot.networkError`. The consuming app owns foreground service deployment.

## Android VPN

Subclass `GnunetVpnService` and declare it with Android's
`BIND_VPN_SERVICE` permission and VPN service action. The app owns the
permission UI and foreground notification. Launch the intent from
`GnunetVpnService.prepareConsent(context)` when Android requires consent.
Declare a single GNUnet VPN service for the application. The process keeps one
VPN grant until its original node and tunnel retire, including across
service recreation.
[Android VPN lifecycle](https://developer.android.com/develop/connectivity/vpn)

Call `startNode(options, maximumPacket = 1500)` from the service on a
background thread after consent. The SDK applies the configured GNUnet
VPN prefixes and MTU with Android's `VpnService.Builder`. Rust duplicates
the original nonblocking tunnel descriptor and handles IP packets. The
service protects each original upstream socket before native use and
rejects sockets that Android does not protect.
[Android descriptor and socket protection](https://developer.android.com/reference/android/net/VpnService)

Use `AndroidNodeOptions.forVpn(context)` for private storage and an empty DNS
configuration. The default `Upstream.SystemDefault` uses Android's protected
socket routing. Physical-network callbacks request address rescans. Native
DNS remains disabled because these callbacks cannot qualify the system
network used for a particular protected socket.

Pass `upstream = Upstream.Pinned(network)` to select an accessible physical
Internet network explicitly. The service binds each original socket to that
network before applying VPN protection and reports it as the VPN's underlying
network. DNS comes from that network's current link properties. Active or
strict Private DNS clears the native DNS upstreams. Both VPN policies reject
manual DNS inputs. Loss of the selected network clears its DNS, requests an
address rescan and prevents new socket binding.
Choose a new network for a new VPN node when the app's policy changes.
[Android network-specific socket binding](https://developer.android.com/reference/android/net/Network#bindSocket(java.io.FileDescriptor)) ·
[Android connectivity callbacks](https://developer.android.com/reference/android/net/ConnectivityManager#registerNetworkCallback(android.net.NetworkRequest,%20android.net.ConnectivityManager.NetworkCallback))

Keep the returned node to observe readiness and await `close()` on a
background thread for app-initiated shutdown. Android revocation or service
destruction fences new packet I/O and socket protection before requesting
shutdown. The join runs asynchronously.
The route worker reports removal after the original Android descriptor closes.
An uncertain close keeps the process reservation.
Use `onVpnRetiring` to retire any additional app-owned VPN resources.
