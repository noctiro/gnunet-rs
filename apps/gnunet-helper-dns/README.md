# gnunet-helper-dns

The privileged Rust helper configures one exclusive TUN interface and exchanges
DNS packets with the service. Standard input/output carry official DNS_HELPER
MQ214 frames with TUN_PI headers. Diagnostics use stderr; the stream has no
setup or packet-delivery acknowledgement.

## Invocation

```text
gnunet-helper-dns IFNAME IPV6ADDR IPV6PREFIX IPV4ADDR IPV4MASK SKIP_ROUTING_SETUP
```

The last argument is exactly `0` or `1`. Deployment supplies effective-root and
group provisioning. The normal caller is `gnunet-service-dns`.

## Platform behavior

Linux supports automatic interception policy or `SKIP_ROUTING_SETUP=1`.
macOS and FreeBSD create native utun/TUN interfaces and use
[delegated PF policy](../../adapters/dns-service-std/PF.md) for automatic routing.
`SKIP_ROUTING_SETUP=1` uses administrator-provided interception/routing instead.
macOS uses `utun` for a free unit or `utunN` for an exact unit. FreeBSD refuses
to adopt an existing interface. The Windows service uses its [native Wintun source](../gnunet-service-dns/README.md#windows-manually-routed-interface).

The [host implementation](../../adapters/dns-service-std/README.md) describes
packet validation, privilege reduction, interface lifetime and independent
cleanup failures. Input and output buffers are reused; each direction retains
its original partial-write/frame cursor.
