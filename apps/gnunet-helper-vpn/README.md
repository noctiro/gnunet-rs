# gnunet-helper-vpn

Linux installed VPN helper, a thin entry over `gnunet-tun-helper-host`. Exact original arguments remain `tun ipv6|- prefix ipv4|- mask`; enabled IPv6
uses1..127 and disabled families ignore their dependent argument. VPN performs
no EXIT forwarding/sysctl/iptables operation. Its original type185+PI stream,
fresh TUN/address/link configuration, bounded pump, credential reduction
and independent native cleanup are shared unchanged in behavior.

Default MTU is never guessed or set. GNUNET_VPN_HELPER_MTU remains an explicit
bounded Rust-only override. No READY/ACK or private wire is added. See the shared
host README for native targets, original FD ownership and synchronous OS bounds. The single signal owner also spans configuration so an early stop is not
reset.
