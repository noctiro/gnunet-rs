# gnunet-helper-nat-client

Official positional CLI: `gnunet-helper-nat-client LOCAL_IP REMOTE_IP PORT` (numeric IPv4, decimal1..65535). No stdin/stdout protocol, configuration loader, private key or subprocess exists. The process opens its raw writer before permanently dropping to the invoking IDs (and Linux capability sets), then parses arguments and sends both official reversal packet variants under one finite5s bound. Exit0 proves only both whole local datagram writes; raw errors/short writes/cancellation produce nonzero and preserve causes. No remote ACK, NAT mapping or connectivity is inferred.

Packet code is shared `gnunet_nat::icmp`; privileged/native operations are isolated in `gnunet-native::nat_helper`. Source dispatch covers Linux, Darwin/macOS and FreeBSD12+; remaining OS targets explicitly return Unsupported. See the host README for exact ABI, lifetime, privilege and cleanup contracts. Source preparation does not install/set SUID or capabilities.
