# Standard DHT SERVICE

`gnunet-service-dht` uses the common SERVICE configuration/options, selected `-L`/`-l` Logger/Reporter and explicit daemon/parent control. It prepares TCP/inherited listeners before USER and completes new Unix listeners with configured access after identity selection. The native DHT owner shares one Broker/SharedClock for the enabled selectors. PILS supplies the public identity and signatures. The GNUnet underlay enables CORE/NSE/PEERSTORE/TRANSPORT; IP-only startup does not require their connections. No private key is read by this app; when CORE is enabled its identity must agree with PILS.

## Native startup and lifetime

Unix owns descriptor transfer and identity changes; Windows owns native
activation/bootstrap, SID verification and qualified parent registration. Both
entries drive the same foreground and real DHT host. Native stop subscriptions
and one bounded parent acknowledgement retain their original owners.

READY stdout is completely flushed only after host readiness, and only then notifies the original parent. Stop, parent/signal failure, Logger, Resolver and host failures retain the same owner through physical close and a once-captured native drain target. Clock failure cannot suppress original CORE source-return retirement. Forced/expired cleanup preserves unresolved prefixes and fails instead of claiming completion. Independent output, Resolver-close and logging errors retain the typed report. No worker, implicit Resolver, detached task or C process is created.

The official DHT bucket/cache/try-connect configuration is consumed; additional `dht-rust` resource limits are explicit. Registry-only revocation settings are used only when both WORKBITS and EPOCH_DURATION exist.

## Underlay selection

The official defaults are `[dhtu-gnunet] ENABLED=YES` and `[dhtu-ip] ENABLED=NO`. The IP section accepts `NSE` (default4) and `UDP_PORT` (default6666, a16-bit
port); enabling both underlays shares the same DHT cache and request owner. Disabling both is a startup error. DHT local SERVICE `HOSTNAME`/`PORT` continue
to select the local client listener, independently of the IP underlay socket.

For a numeric explicit interface bind, `[dht-rust] IP_BIND=127.0.0.1` (or an
IPv6 address) restricts the IP socket family/address. Omitting it uses the IP
backend's wildcard binding. `IP_BIND` with the IP backend disabled is refused. These settings choose sockets and address candidates; they do not prove
remote reachability. The original `[dht] DISABLE_TRY_CONNECT` gates new HELLO
candidate dialing through either backend. Runtime use remains subject to the
platform socket/interface results.

## Direct IP host

Interface snapshots retain native scope and prefix information. Windows excludes
tentative/duplicate addresses from local source candidates and disables ICMP
port-unreachable receive resets on the original UDP socket. Isolated datagram
errors do not retire the shared underlay or authenticate an earlier send.
