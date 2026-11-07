# gnunet-service-core

Thin foreground entry for `gnunet-core-host`: `gnunet-service-core -c official.conf`. Uses official `[core]` listener/CLASS settings, `[pils]` and `[transport]` CLIENT
endpoints and the existing private raw32 `[PEER] PRIVATE_KEY`. Inherited activation
descriptors are captured before other initialization. Newly bound paths are owned
by the shared service runtime and removed after their sockets close.

SIGINT/SIGTERM immediately closes original application/monitor/TRANSPORT owners
and drops session keys. Readiness reports only the verified public identity;
shutdown reports public counters. No private keys/plaintext are logged. No C
backend, daemonization or user switching is supplied by this entry. The host can
instead be embedded with an external Rust identity and canonical process clock.

This is a CORE component service. Full-node conformance still requires the other
Rust services and source-bound end-to-end validation of the selected profile.
