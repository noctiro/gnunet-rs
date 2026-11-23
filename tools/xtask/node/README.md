# Native node staging

`cargo xtask stage-node` builds and stages a relocatable native prefix for
Linux, macOS, Windows or FreeBSD. Run it from the repository root.
See the [node SDK](../../../platform/sdk/README.md) for application bindings.

```sh
cargo xtask stage-node --output target/gnunet-node --jobs 1
```

The command takes release executables from Cargo's completed build. It places
public commands in `bin`, services and helpers in `lib/gnunet/libexec`, and
the bundled peer defaults in `share/gnunet/config.d`. Choose a new output
directory under a parent you control. The command assembles the artifacts,
configuration and supplied platform providers in a temporary sibling, then
publishes the complete prefix without overwriting an existing entry.
The prefix includes the project license, [source notices](../../../NOTICE.md)
and the selected Cargo dependencies' license texts under `share/doc/gnunet`.
Supply any separate notices for externally provided components you redistribute.

Omit `--target` for the toolchain's host definition. Select a different Rust
target triple with `--target TRIPLE` when its Rust target and native linker are
available. Use the target platform's packaging tools to preserve Unix
executable modes when distributing a prefix assembled on Windows.

## Deploy as an operating-system service

Each desktop prefix includes the selected platform's service assets and
deployment instructions in `share/gnunet/service`. For Linux, macOS and
FreeBSD, the service definition uses the final install location selected by
`--install-prefix` (default `/usr/local`), independent of the staging path
selected by `--output`. For example:

```sh
cargo xtask stage-node --output target/gnunet-node --install-prefix /opt/gnunet --jobs 1
```

Use an absolute Unix path with normalized components made up of letters,
digits, dots, underscores, plus or hyphens. Windows uses the executable path
given when registering the service, so it does not take `--install-prefix`.
Follow the staged `README.md` to
prepare the service account, state and IPC directories, and install the
manager configuration. The manager runs `bin/gnunet-node` (or
`bin/gnunet-node.exe`) as a single process.

| Target | Service manager and deployment guide |
| --- | --- |
| Linux | [systemd](../../../platform/linux/node/README.md) |
| macOS | [launchd](../../../platform/macos/node/README.md) |
| FreeBSD | [rc.d](../../../platform/freebsd/node/README.md) |
| Windows | [Service Control Manager](../../../platform/windows/node/README.md) |

## Stage a system image input

`stage-node-image` builds the foreground `gnunet-node` for an Android image,
an OpenHarmony standard-system image or HiSpark Taurus Linux small system.
It stages the executable, licenses and matching build and init files. Supply
the Rust target and product cross-linker configuration before staging. The
default build limit is one job.

```sh
cargo xtask stage-node-image --target aarch64-linux-android \
  --output target/gnunet-node-android-system
cargo xtask stage-node-image --target aarch64-unknown-linux-ohos \
  --policy /path/to/node-image.json --output target/gnunet-node-ohos-system
cargo xtask stage-node-image --profile openharmony-small-linux \
  --target armv7-unknown-linux-musleabi --policy /path/to/taurus-node.json \
  --output target/gnunet-node-taurus
```

Android uses the [vendor recipe](../../../platform/android/system/README.md)
and the product's `vendor_gnunet` account. OpenHarmony requires a JSON policy
with the product's actual IDs, domain and part registration. Replace the
example policy values with the corresponding board allocations.

```json
{
  "uid": 3401,
  "gid": 3401,
  "selinux_context": "u:r:gnunet_node:s0",
  "part": "gnunet_node",
  "subsystem": "custom",
  "state_directory": "/data/gnunet/state",
  "ipc_directory": "/data/gnunet/ipc",
  "peer_mode": "outbound-tcp"
}
```

`peer_mode: "listening"` requires `udp4_bind` and either a numeric
`tcp_bind` or a nonzero `tcp_dual_stack` port. `udp6_bind` is optional.
`config_file` and `bootstrap_data_directory` select immutable paths under
`/system`. `dns_servers` accepts explicit numeric IP and port pairs.
The generated init command must fit its 20-argument and 64-byte-per-argument
limits.

The [OpenHarmony standard-system recipe](../../../platform/openharmony/system/README.md)
describes product registration, storage and the stop contract. The
[HiSpark Taurus small-system recipe](../../../platform/openharmony/system/small-linux/README.md)
uses separate policy paths and supplies the required Linux `/storage` mount.
Each image integrator supplies the service identity and applicable product policy.

Add `--include-nat-helpers` to stage both native ICMP traversal helpers for
the same target and select their installed directory in the generated init
command. The Android recipe installs the pair in `/vendor/bin` and the
OpenHarmony recipe installs it in `/system/bin`. This selection uses two
OpenHarmony init arguments. The board supplies executable capabilities and
SELinux policy for the pair.

## Run the staged ARM-managed services

On a POSIX shell:

```sh
export GNUNET_PREFIX="$PWD/target/gnunet-node"
export GNUNET_BASE_CONFIG="$GNUNET_PREFIX/share/gnunet/config.d"
export PATH="$GNUNET_PREFIX/bin:$PATH"
config="$GNUNET_PREFIX/share/gnunet/node.conf"
gnunet-arm -c "$config" -s
gnunet-statistics -c "$config"
gnunet-arm -c "$config" -e
```

On Windows PowerShell:

```powershell
$env:GNUNET_PREFIX = (Resolve-Path target/gnunet-node).Path
$env:GNUNET_BASE_CONFIG = Join-Path $env:GNUNET_PREFIX share/gnunet/config.d
$env:Path = "$env:GNUNET_PREFIX\bin;$env:Path"
$config = Join-Path $env:GNUNET_PREFIX share/gnunet/node.conf
gnunet-arm.exe -c $config -s
gnunet-statistics.exe -c $config
gnunet-arm.exe -c $config -e
```

The environment selects the staged binaries and defaults. The explicit `-c`
file supplies local overrides independently of the standard user configuration.
Use a separate copy of `node.conf` for local overrides. The profile creates
per-user Rust state and owner-only IPC sockets. To run multiple local nodes,
give each an independent `GNUNET_DATA_HOME` and `GNUNET_RUNTIME_DIR` in its
configuration.

## Peer connections and platform components

The bundled ARM communications configuration listens on loopback. Override the
TCP and UDP bind addresses for connections from other hosts. Supply signed
peer HELLOs through [gnunet-hello](../../../apps/gnunet-hello/README.md)
or stage a directory of HELLO URI files with `--hello-dir PATH`. Staged HELLOs
are loaded by PEERSTORE on startup.

On GNU Linux the staged `lib` contains the three NSS loader names. System
activation follows the [NSS deployment guide](../../../adapters/gns-nss-std/README.md#loader-artifact-and-administrator-configuration).
The [macOS DNS provider](../../../apps/gnunet-service-dns/macos/README.md) and
[Windows WFP driver](../../../platform/windows/wfp-driver/README.md#package-preparation)
use platform-specific activation.

On macOS, include an externally signed DNS containing app with
`--macos-dns-app APP.app`. Staging checks that both components support the node
architecture and verifies the signed app before and after copying it to
`share/gnunet/providers/macos`. Deploy the complete staged app from
`/Applications`. [macOS DNS activation](../../../apps/gnunet-service-dns/macos/README.md#stage-and-activate-a-signed-application)

Include a prepared Windows WFP package in the node prefix with `--wfp-package`.

```sh
cargo xtask stage-node --target x86_64-pc-windows-msvc --jobs 1 \
  --output target/gnunet-node-windows --wfp-package target/wfp/package
```

Supply the matching `gnunet-wfp-driver.sys`, `gnunet-wfp-driver.inf` and signed
`gnunet-wfp-driver.cat` together. The selected Windows target may be x64 or
ARM64. Staging checks the package structure and preserves the three files
under `share/gnunet/providers/windows/wfp`. Windows verifies the catalog's
signature, trust and file associations during deployment. Follow the
[WFP package preparation guide](../../../platform/windows/wfp-driver/README.md#package-preparation)
for installation and activation.

## Message catalogs

Use `--locale-dir PATH` to include compiled GNU GNUnet message catalogs.
The input uses the installed locale layout
`<locale>/LC_MESSAGES/gnunet.mo`. Staging copies the catalogs into
`share/locale`, where commands and services select them from the original
locale environment. Compile source translation files with GNU `msgfmt` before
staging. [Catalog selection](../../../adapters/program-std/NATIVE-CONTRACT.md#installed-message-catalogs)

## Linux testing tools

The Linux prefix includes `gnunet-testing-netjail-launcher` and its command
helper. [Netjail usage](../../../apps/gnunet-testbed/README.md#linux-netjail-launcher)

## Optional service profiles

Profiles are installed in `share/gnunet/profiles`. Add the selected files to your
copy of `node.conf` while keeping `GNUNET_BASE_CONFIG` pointed at the bundled
`config.d`. An `@INLINE@` directive takes a literal filename, including spaces,
without quotes or environment expansion. Place local settings after the imports
to override them. Restart ARM with the amended `-c` file to load its new service
registry. Use the same `-c` file for clients and for starting individual services.

```ini
@INLINE@ /absolute/path/to/gnunet-node/share/gnunet/profiles/quic.conf
@INLINE@ /absolute/path/to/gnunet-node/share/gnunet/profiles/regex.conf
```

| Profile | Effect when included |
| --- | --- |
| `quic.conf`, `http3.conf` | Start the selected communicator with a dynamically assigned loopback port. Supply a matched `KEY_FILE` and `CERT_FILE` to use a configured TLS identity. |
| `unix-communicator.conf` | Register the test UNIX datagram communicator on Linux, macOS and FreeBSD. Give parallel test nodes separate runtime directories and start each communicator with `gnunet-arm -c "$config" -i communicator-unix`. See the [wire and trust constraints](../../../adapters/unix-communicator-std/README.md#wire-format-and-platform-constraints). |
| `regex.conf`, `sets.conf`, `rps.conf` | Register REGEX, generic SET and SETI, or RPS on owner-local endpoints. SETU is in the base defaults. |
| `abd.conf`, `reclaim.conf` | Register the respective credential service. Applications supply local IDENTITY egos through the normal interfaces. |
| `consensus.conf` | Register CONSENSUS and its generic SET dependency. |
| `scalarproduct-ecc.conf`, `scalarproduct-paillier.conf` | Select one variant for the node's shared Alice and Bob endpoints. Both profiles include SETI. |
| `messenger.conf`, `conversation.conf` | Register Messenger with durable history, or Conversation call signaling. The [Conversation command](../../../apps/gnunet-conversation/README.md) configures audio separately. |
| `nat-auto.conf` | Register the NAT configuration proposal service on an owner-local endpoint. |
| `hostlist.conf` | Register an HTTP hostlist publisher for explicit start. It listens on loopback port 8080. |
| `rest.conf` | Register REST for explicit start and RECLAIM on demand. REST uses loopback port 7776 and Basic authentication. |
| `dns.conf` | Register DNS interception for explicit start after selecting an upstream and deploying a packet provider. |
| `dns2gns.conf`, `gns-proxy.conf` | Register the DNS2GNS gateway or the GNS proxy for explicit start on loopback ports 15353 and 7777 respectively. |
| `bcd.conf` | Register the GNS business-card HTTP server for explicit start on loopback port 8888. |
| `secretsharing.conf` | Register SECRETSHARING and its CONSENSUS and SET dependencies. |
| `pt.conf` | Register PT. Select the interception stages and start it explicitly. |
| `exit-dns.conf`, `exit-ip.conf`, `vpn.conf` | Register a DNS EXIT, IP EXIT or VPN for explicit start after local configuration. Select one EXIT profile. |

Start HOSTLIST with `gnunet-arm -c "$config" -i hostlist`. It serves the node's
known peer records. Bootstrap downloads, learning and advertisement require
their own flags and sources. Start REST with `gnunet-arm -c "$config" -i rest`
after PILS initializes the data directory. REST creates a private random
password file at `BASIC_AUTH_SECRET_FILE` when the file is absent. By default
the Basic username is the account running REST. Configuration writes target
the dedicated `CONFIG_OUTPUT` file. See the
[REST configuration reference](../../../apps/gnunet-rest-server/CONFIGURATION.md)
for authentication and OpenID Connect settings.

Query NAT proposals with `gnunet-nat-auto -c "$config" --auto`. Enable the
desired traversal providers in `[nat]` for the host. Separate TCP and UDP
reachability tests require a reachable `[gnunet-nat-server]` and the tested
adapter's `PORT`. [NAT configuration](../../../apps/gnunet-nat-auto/README.md#configuration-and-examples)

For DNS2GNS, set `[dns2gns] OPTIONS` to `-d` followed by the numeric address
of a reachable recursive resolver. Check `BIND_TO`, `BIND_TO6` and `PORT` for
the intended DNS listener, then start `dns2gns` with ARM. Use a typed zone
key in the name or configure the public key for a named `[gns] .suffix`.
VPN-backed records also require VPN.
[DNS2GNS configuration](../../../apps/gnunet-dns2gns/README.md#configuration-and-invocation) ·
[GNS name routing](../../../adapters/gns-api-std/README.md)

For the GNS proxy, prepare a combined CA certificate and private-key PEM at
`[gns-proxy] PROXY_CACERT`, then start `gns-proxy` with ARM. The client must
trust the selected CA to use HTTPS through the proxy.
[CA preparation](../../../apps/gnunet-gns-proxy-setup-ca/README.md#credential-publication)

Start BCD with `gnunet-arm -c "$config" -i bcd`. Select `[bcd-rust] PDFLATEX`
for PDF generation and `GHOSTSCRIPT` for QR PNG rendering as needed. Windows
requires explicit absolute paths to the installed tools.
[BCD configuration](../../../apps/gnunet-bcd/CONFIGURATION.md#listener-and-tools)

SECRETSHARING supports threshold-one generation when the roster is empty or
contains only the local peer, and decryption with existing shares. General
multiparty generation remains limited by the official FAIR envelope.
[SECRETSHARING operations](../../../apps/gnunet-service-secretsharing/README.md#operations-and-ownership)

PT requires the configured [DNS interception service](#dns-interception). Set
`[pt] TUNNEL_DNS=YES` for pre-resolution queries tunneled through DHT-discovered
CADET exits. Set `TUNNEL_IPV4=YES` or `TUNNEL_IPV6=YES` for post-resolution
address translation through VPN. Load and configure `vpn.conf` when selecting
address translation. Start PT with `gnunet-arm -c "$config" -i pt` after
preparing its providers.
[PT configuration](../../../apps/gnunet-daemon-pt/README.md#configuration)

For IP EXIT, select `[exit] ENABLE_IPV4=YES` with `IPV4ADDR` and `IPV4MASK`,
or `ENABLE_IPV6=YES` with `IPV6ADDR` and `IPV6PREFIX`, using addresses assigned to
this node. Named services use `TCP_REDIRECTS` or `UDP_REDIRECTS` in `.gnunet.`
sections. To offer Internet access, select `EXIT_IPV4=YES` or `EXIT_IPV6=YES` and set the
matching `EXIT_RANGE_IPV4_POLICY` or `EXIT_RANGE_IPV6_POLICY`. Start EXIT with
`gnunet-arm -c "$config" -i exit`.

For Linux fresh IP EXIT, set `TUN_IFNAME` and install the privileged native
helper separately. Choose `EXIT_IFNAME` if the helper should configure
forwarding and IPv4 masquerading on a physical interface. `%` leaves egress
configuration to the operator. macOS and FreeBSD use native devices and require
host routing, forwarding and firewall configuration. On Windows, set `TUN_IFNAME`
and the absolute `[exit-rust] WINTUN_DLL` path, and configure host forwarding and
firewall policy. The same profile supports the device provider settings and
named redirects in the EXIT configuration reference.
[EXIT configuration](../../../apps/gnunet-daemon-exit/CONFIGURATION.md#startup-and-configuration)

For EXIT DNS, set `[exit] DNS_RESOLVER` to a numeric address of a resolver the
node can reach. Use `[exit-rust] DNS_RESOLVER_PORT` when it differs from 53.
Then start `exit` explicitly. This profile uses CADET for DNS and opens no TUN
device. For VPN, choose the actual interface name, address and device provider
before starting `vpn`. Supply `[vpn-rust] CONFIGURED_EXITS` or add `regex.conf`
and select `EXIT_DISCOVERY=regex`. Set `[vpn] UNIX_MATCH_UID=YES` on Unix to
enforce peer credential checks. Linux uses the separately authorized native helper in fresh
mode. macOS uses a native `utunN` and FreeBSD a native TUN. Windows uses an
owner-only endpoint and requires an explicit trusted `WINTUN_DLL` path. The
[VPN device requirements](../../../apps/gnunet-service-vpn/CONFIGURATION.md#device-selection)
and [EXIT configuration](../../../apps/gnunet-daemon-exit/CONFIGURATION.md)
describe permissions, routing and available providers.

### DNS interception

Include `dns.conf` and set `[dns] DNS_EXIT` to the numeric unicast address of
the resolver that should receive upstream queries. Set `[gns] INTERCEPT_DNS=YES`
if GNS should handle intercepted queries. Keep DNS clients and the service on
the same configured IPC endpoint.

- **Linux** uses `[dns-rust] LINUX_BACKEND=TPROXY` for transparent UDP ingress.
  Set `TPROXY_PORT`, `TPROXY_INTERFACES` and `TPROXY_BYPASS_MARK` for the host.
  Provision the corresponding ingress interception and policy route, and grant
  the service permission to open transparent sockets and set socket marks.
  [Linux transparent ingress](../../../apps/gnunet-service-dns/README.md#linux-transparent-ingress)
- **Windows** uses `[dns] SKIP_ROUTING_SETUP=NO` with either `[dns-rust]
  WINDOWS_BACKEND=WFP` for the installed GNUnet WFP driver or
  `WINDOWS_BACKEND=WINDIVERT` for an installed WinDivert 2.2 driver. WinDivert
  requires the absolute `WINDIVERT_DLL` path and an account with native
  administrator privileges. WFP's default device ACL admits LocalSystem. The
  default DNS local endpoint admits the service account.
  [Windows automatic interception](../../../apps/gnunet-service-dns/README.md#windows-automatic-interception)
- **macOS** uses the separately signed and deployed DNS system extension. The
  containing application's `gnunet-dns-control enable --config PATH` takes a
  complete configuration at an absolute path. Bundle the selected defaults in
  the extension's `Contents/Resources/share/gnunet/config.d` or supply them in
  that configuration. Check endpoint access from the extension and its
  clients. The OS starts the provider.
  [macOS provider deployment](../../../apps/gnunet-service-dns/macos/README.md)
- **FreeBSD** leaves staged interception inactive. The native receiving path
  still requires capture and delivery bound to the original interface and socket.
  [FreeBSD receiving path](../../../adapters/dns-service-std/NATIVE_BACKENDS.md#freebsd-receiving-path)

On Linux and Windows, start DNS with `gnunet-arm -c "$config" -i dns` when ARM
runs under the account authorized to use the provider. For a different account,
invoke `gnunet-service-dns` from the staged `lib/gnunet/libexec` directory with
`-c PATH` and run its local phase clients under the same account.
