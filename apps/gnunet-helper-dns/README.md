# gnunet-helper-dns (Rust)

Linux fixed-purpose privileged helper. The production executable accepts the official six arguments: `IFNAME IPV6ADDR IPV6PREFIX IPV4ADDR IPV4MASK SKIP_ROUTING_SETUP`, with the last argument0 or1. Standard input/output are exclusively the official DNS_HELPER214 MQ plus TUN_PI/raw IP stream. Diagnostics go to stderr. No READY/configuration/TUN-written ACK exists or is added.

It delegates to `gnunet_dns_service_host::platform::run` on a caller-created current-thread runtime. Configuration, packet pump, native short-write/loss and independent control/TUN cleanup are operations when run. The executable must receive privilege/group provisioning by deployment; no C helper, shell, key fixture or generic command-execution interface is embedded.
