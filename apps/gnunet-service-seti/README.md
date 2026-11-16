# SETI service

`gnunet-service-seti` implements the official GNUnet SETI IPC and Bloom exchanges
through the configured CADET client. The protocol core, bounded slot pools and
source/operation retirement stay in the SETI core and host layers.

## Startup and configuration

Run `gnunet-service-seti -c service.conf`. The shared
[native SERVICE driver](../../adapters/program-std/README.md#service-startup)
provides `-c/-d/-h/-L/-l/-v`, standard configuration loading, selected diagnostics,
process identity, inherited listeners and original-parent control/readiness.
Unix uses privilege changes and fork detachment; Windows uses process-token
verification, native activation, managed console detachment or standalone re-exec.

`[seti]` supplies endpoints, ACLs, `USERNAME`, Unix credential policy and `TOLERANT`.
`[cadet]` supplies the carrier; `[seti-rust]` selects finite slot, work, memory and
time bounds. Explicit Unix UID/GID checks remain unsupported on Windows. Native
endpoint ACLs and configured process identity retain their own mechanisms.
See the [host configuration and wire profiles](../../adapters/seti-std/README.md)
for the resource keys and explicit counterpart ABI.

## Readiness and shutdown

One shared clock reaches the selected Reporter, Resolver and SETI/CADET owners.
Readiness requires actual CADET attachment. After the final stop check, the service
writes its READY line and submits the original startup status through a finite wait
that still observes logging and native/parent stop. This proves local initialization.

A soft stop captures one native grace target. Native guards run before canonical
or Resolver work, including continuously ready traffic. Logging failure fences
new work; the same server and Resolver are physically retired. Every fallible path
after server construction reaches its close seam. Original failures, independent
native cleanup, Resolver disconnect, stdout errors and entropy failures remain
separate. STOPPED retains `remote-drain=not-claimed`.
