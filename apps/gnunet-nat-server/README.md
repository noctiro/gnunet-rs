# gnunet-nat-server

Rust foreground for official Test protocol; shared PROGRAM/activation/credentials/Resolver/clock. No private GNUnet messages or success ACKs. See gnunet-nat-host N3 README for original provider/mapping/helper/cleanup boundaries. Requires separately built Rust helpers for ICMP traversal on supported OS; service does not change helper ownership/capabilities/permissions automatically. READY establishes local listener ownership only. STOPPED reports remaining/uncertain cleanup, not remote connectivity.
