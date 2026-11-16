# gnunet-daemon-pt

Translate intercepted DNS answers through VPN allocations, or tunnel DNS queries
to DHT-discovered exits over CADET. The shared PROGRAM foreground supports Linux,
macOS, Windows and FreeBSD. PT creates no listener or device; DNS interception and
packet forwarding are supplied by the DNS and VPN services.

## Configuration

Install [pt.conf](pt.conf) in the shared configuration directory and the binary
in libexec. The official switches default to NO:

```ini
[pt]
TUNNEL_IPV4 = YES
TUNNEL_IPV6 = YES
TUNNEL_DNS = NO
```

Enabled address families select DNS and VPN clients. TUNNEL_DNS selects PRE DNS,
DHT discovery and CADET. Disabled functions create no endpoint selectors; with
all switches disabled the daemon exits normally. `[pt-rust]` supplies finite
resource and timeout settings described by the [host](../../adapters/pt-std/).

```sh
gnunet-daemon-pt -c gnunet.conf -L INFO
```

No positional arguments are accepted. `-L` selects the diagnostic level and `-l`
selects a log file.

## Startup and shutdown

Client startup captures original inheritance before native initialization and
refuses service-listener activation. Unix applies configured process privileges;
Windows verifies the configured identity against its process token. The shared
stop subscription handles native termination and parent-control bytes. PT has
NOARMBIND=YES and sends no listener READY.

The foreground owns one PROGRAM Resolver and clock. On stop or failure it
retires DNS/VPN/CADET/DHT work, drains STATISTICS within its original bound and
disconnects the Resolver, preserving independent cleanup and diagnostic errors.
Protocol and lifecycle contracts are documented in the
[host README](../../adapters/pt-std/README.md); native runtime qualification remains
in [implementation status](../../IMPLEMENTATION_STATUS.md).
