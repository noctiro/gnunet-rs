# ABD service

`gnunet-service-abd -c service.conf` runs the official ABD application endpoint
using caller-driven GNS and private NAMESTORE sources. Each application may retain
multiple original request IDs; results count only after their original IPC frames
write in full.

## Startup and configuration

The shared [native SERVICE driver](../../adapters/program-std/README.md#service-startup)
provides standard options, selected diagnostics, listeners, process identity,
original parent control and bounded readiness submission. Unix prepares inherited
and TCP listeners before privilege changes, then completes local endpoints under
the configured identity. Windows verifies the process token, imports activation,
and uses managed console detachment or qualified standalone re-exec.

`[abd]` selects listeners, ACLs and service options. Missing Unix credential
settings default to UID/GID matching on Unix and neither check on Windows.
Explicit Unix UID/GID checks remain unsupported on Windows; native endpoint ACLs
retain their separate policy. RUN_PER_USER remains the official deployment model.

`[abd-service-rust]` selects finite client/query and aggregate reservations,
input/operation/output/shutdown bounds, trusted-clock uncertainty, proof
node/rule/term/depth/fact/witness/lookup/name/credential capacities, explicit
`ATTR_ALIGN64`, and GNS/NAMESTORE/Resolver resources. The shared clock has 4096
waiter slots. Invalid resource profiles fail before listener or business admission.

## Results and retirement

READY means bound listeners and IPC admission. Dependency connections and proof
readiness are established by each original request. A negative result requires
actual source and proof completion. Timeout, source loss or resource refusal does
not manufacture authorization or a completed negative result.

Client closure physically retires its original MQ before canceling its queries.
Original failures and independent cleanup remain separate. Source or profile
errors do not replay work on another source. See the
[host contracts](../../adapters/abd-std/) and
[compatibility policy](../../spec/gnunet/compatibility.md).
