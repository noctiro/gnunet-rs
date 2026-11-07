# Shared live transport port

`transport::LiveConfiguration::{new,snapshot,replace}` is a caller-retained,
coherent configuration object. `Endpoint::configuration_live(service,resolver,
section)` validates and caches TCP when the logical MQ is constructed. At the
start of each even/no-TCP physical attempt only UNIXPATH is sampled again.
Replacing the store performs no network operation or wake and never replaces
an already-polled attempt or established stream. `Configuration` remains the
existing byte-preserving official configuration model; there is no private wire
or configuration grammar in this port.

Resolver input is explicitly independent. It is sampled at a nonnumeric lookup,
not installed as a process-global PROGRAM broker. The lookup's internal retries
currently retain that snapshot. The full shared Resolver MQ lifecycle and
PROGRAM resolver_cfg replacement behavior remain pending; this port does not
claim to complete them.

Production uses no additional registry dependencies and retains forbid unsafe.
The standalone candidate package rename exists only to coexist with the formal
IPC dependency in a temporary Cargo graph. Merge these four source changes into
the formal gnunet-ipc-unix package; do not rename that package or copy the
standalone manifest. ARM ownership tests exercise this public generic port.
