# gnunet-service-nat

Normal Rust foreground for official NAT IPC, using shared PROGRAM, activation,
credentials, Resolver and clock owners. READY establishes local listener ownership; notifications and remote
connectivity require their own observations.

Interface, STUN, UPnP and native helper paths retain their separate runtime
qualification requirements. Supported ICMP traversal requires separately built
Rust helpers; the service does not change their ownership, capabilities or
permissions. See the gnunet-nat-host N3 README for provider, mapping, helper and
cleanup boundaries. STOPPED reports remaining or uncertain cleanup.
