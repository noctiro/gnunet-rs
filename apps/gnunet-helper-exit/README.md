# gnunet-helper-exit

Linux installed helper using the small `gnunet-tun-helper-host` implementation. Exact arguments: `tun egress|- ipv6|- prefix ipv4|- mask`. EXIT needs at least
one IP family; enabled IPv6 prefix1..127. Output is only official type185 frames
with the original PI4 and raw IP, with no READY/banner/ACK.

With egress enabled, forwarding/sysctl and IPv4 MASQUERADE commands must
succeed before TUN setup. Their captured output never reaches the framed stdout. Global forwarding/NAT settings remain after exit or partial failure, as in C;
no other's rule is deleted and no restoration is claimed. Default MTU is observed,
not changed; GNUNET_VPN_HELPER_MTU is an explicit Rust-only shared extension. See the shared host README for original child wait/error and packet/FD bounds.
