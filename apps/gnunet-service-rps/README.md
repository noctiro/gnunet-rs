# Normal RPS service

`gnunet-service-rps` implements the active GNUnet v0.29.1 RPS service IPC and
Brahms peer exchange through the existing official CADET client. The pure core,
native service reactor and normal process entrypoint remain separate. No
production libgnunet FFI or private network framing is used.

The normal SERVICE shell loads official options/configuration, adopts inherited
listeners once, applies the configured identity before finishing new Unix
listeners, and shares one canonical clock and explicitly driven Resolver. Startup obtains the local identity from a CORE INIT_REPLY. READY follows
CADET attachment and the main port's whole original announcement write. A changed CORE identity stops the original RPS process rather than silently
relabeling its groups. Ordinary source retries retain their causes.

A separate foreground actor observes CORE status changes, PEERSTORE HELLO
record keys and NSE estimates. Cached peer identifiers are only discovery hints;
matching CADET traffic qualifies peers. The actor preserves each original
monitor lease, credit debt, epoch and terminal observation. The existing CORE
client has an explicit fixed 4096-neighbor metadata profile. NSE resize targets
are bounded; non-finite estimates do not become allocation targets.

`[rps] MINSIZE` and `ROUNDINTERVAL` select the initial view/sampler and mean
round interval, defaulting to 10 and 30 seconds. `[rps-rust]` separately bounds
clients, groups, known peers, samplers, retained core bytes, effects, CADET
channels and native queues. `STARTUP_TIMEOUT`, `SHUTDOWN_GRACE`, and the
first/partial/write phase limits are independent finite bounds. UID/GID
credential policy and inherited/default configuration follow the shared SERVICE
runtime. `IPC_NATIVE_BYTE_ORDER` explicitly selects the current C reply-count
ABI when needed; no wire negotiation or alternate parser is added.

Subgroups use the official 64-byte derived CADET port value and distinct local
generations. The main port is SHA512 of `rps`; subgroup derivation uses the
existing GNUnet HKDF. Old group/peer work remains blocked until its actual
channel retirement. Known close and reannouncement obligations are not remote
application acknowledgements. Sample requests are local SDK sampler demand;
service replies contain the biased stream or view, with no invented
request-N, ACK or END message.

Every exit retires the original service, CORE, PEERSTORE, NSE and Resolver
owners. Queued/admitted effects and whole/partial writes remain distinct;
cleanup errors and original monitor Completed/Lost facts are retained. The
service adds no detached worker or task. Internal valid-peer hints are rebuilt
from the current discovery sources; no migration of C's private cache format is
required or claimed.

This source composition has not yet been accepted against an RPS C
service or mixed peer network. Static compilation, runtime interoperability and
measured memory/performance are separate evidence scopes. The conditional
upstream malicious mode is not a normal service capability.
