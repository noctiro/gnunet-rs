# NSE service

`gnunet-service-nse -c official.conf` composes the Rust NSE owner, native
CORE/PILS clients, exact raw8 proof storage and configured local/TCP listeners.
It uses no C service backend.

## Configuration

The shared SERVICE options are `-c/-d/-h/-L/-l/-v`; `-v` prints the version.
Official defaults are `WORKBITS=15`, `INTERVAL=1h` and `WORKDELAY=5ms`.
`PROOFFILE`, endpoint/ACL settings and `[PILS] PROFILE` select actual resources.
See the [host API](../../adapters/nse-std/) for work, framing, proof recovery and
statistics contracts.

Unix `UNIX_MATCH_UID` takes priority over `UNIX_MATCH_GID`. Both default false;
malformed values fail configuration. Checks precede framing and pure START
allocation. Windows protects local endpoint paths through native ACLs; an
explicit Unix UID/GID request remains an `Unsupported` error, with no invented
SID-to-UID translation. TCP admission uses configured address ACLs.

## Native startup

Unix captures inherited listeners/control before options and detaches only at
the fresh-process boundary. The idle current-thread runtime prepares TCP and
activation before the configured account transition; new local paths finish
under the selected account. No async task changes process identity.

Windows captures native activation/bootstrap first, verifies the configured
process SID and uses the qualified parent and native detachment owners. Both
entries register stop subscriptions before proof or business work and drive one
common foreground with the selected Reporter and shared clock.

## Readiness and shutdown

`READY <public-key-hex>` is flushed after verified PILS/CORE agreement and actual
NSE activation. Only then does the driver poll the original parent notification.
Its fixed deadline observes native stop and diagnostic failure; startup cannot
succeed merely because listeners bind or the control stream reaches EOF.

Termination closes original client/subscriber scopes and flushes pending proof
progress before exit. The ten official nonpersistent STATISTICS keys use the
shared original-source producer. Service, proof, logging, statistics and Resolver
cleanup failures retain independent causes. `STOPPED` contains public counters,
commit receipts and the actual directory-barrier observation; Windows does not
claim a completed directory barrier.
