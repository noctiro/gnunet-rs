# Ordinary CONVERSATION service source

`gnunet-service-conversation` composes local IPC, per-Line call cores and
original CADET/PILS sources. The conditional fixed C service uses option NONE
and explicit Unix UID=NO/GID=YES; these defaults are retained. Ordinary early
inherited descriptor capture, fresh-process daemon transition, USERNAME before
Unix listener finish, socket binding, selected Logger/shared Clock,
explicit Resolver, parent control and signals use the normal facilities.

Node-wide `[PILS] PROFILE` selects the native identity verifier. Optional `[conversation-service-rust] PILS_PROFILE` must agree with an explicit
node choice. The default is `reference029`; `deterministic` and its
`reference-deterministic` alias select the official conditional build. `lsd0014-text` remains an explicit, separate published derivation, without a
verification fallback or official C build qualification. These settings do not
change wire formats or grant replacement-MQ recovery. Healthy same-observer peer
changes retain registered ports and original channels; their ringing signatures
keep the local target captured when each incoming channel was admitted.

READY means local IPC listeners and admission, not connected PILS/CADET,
verified remote ringing, pickup, publication or sound-device readiness. Each
Line owns private caller frames and native source state independently. The caller ego key is not the network peer identity. Exact original delivery,
partial/whole writes and source identities reach the host/core, never a
new remote ACK. Clock-free source retirement and independent cleanup precede
STOPPED; undrained original debt forbids a successful stop claim.

[conversation-service-rust] configures global Lines/calls, per-Line core and
CADET/PILS/HELLO resources, UTC uncertainty and original startup,
first/partial/peer/ringing/write/close/shutdown bounds. The shared clock has4096
finite waiter slots. Same-MQ calls retain their own original authorities;
ordinary application logging never dumps private keys or audio data. Frame,
queue and reservation quotas are not process RSS or throughput measurements.

This service does not open sound devices, publish phone records or implement
an implicit GNS caller: those belong to the ordinary client/media workflow. Complete unchanged-C peer interoperability, audio/device behavior and measured
resource/performance qualification remain separate work.
