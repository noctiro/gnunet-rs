# Conversation service

`gnunet-service-conversation -c service.conf` composes official local IPC,
per-Line call state and original CADET/PILS sources. Each Line owns its caller
frames and native source state. Caller ego keys and network peer identities
remain distinct.

## Startup and configuration

The shared [native SERVICE driver](../../adapters/program-std/README.md#service-startup)
provides standard options, selected diagnostics, configured identity, listeners,
original parent control and stop subscriptions. Unix uses privilege changes and
fork detachment; Windows verifies the process token and uses native activation,
managed console detachment or qualified standalone re-exec.

`[conversation]` selects the official listener and service options. Missing Unix
credential settings default to UID=NO/GID=YES on Unix and NO/NO on Windows.
Explicit Unix UID/GID checks remain unsupported on Windows; endpoint ACLs retain
their native policy. Node-wide `[PILS] PROFILE` selects the identity-verification
profile; an explicit local `PILS_PROFILE` assertion must agree.

`[conversation-service-rust]` selects Lines/calls, per-Line core and
CADET/PILS/HELLO resources, UTC uncertainty and finite startup, input, peer,
ringing, write, close and shutdown bounds. The shared clock has 4096 waiter slots.

## Readiness and ownership

READY denotes listener and IPC admission. It does not promise verified remote
ringing, pickup, publication or sound-device readiness. The original parent
notification has a bounded wait that observes logging and native/parent stop.
Partial/whole writes and source identities reach their original owners; local
completion never manufactures a remote acknowledgement. Physical retirement
and independent cleanup precede STOPPED. Undrained original debts prevent a
successful stop claim.

Sound devices, phone-record publication and GNS calling belong to the
[client/media workflow](../gnunet-conversation/). The central
[implementation status](../../IMPLEMENTATION_STATUS.md) tracks remaining profiles.
