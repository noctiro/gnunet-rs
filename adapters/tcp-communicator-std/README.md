# TCP communicator host

Communicator owns one process-level PEERSTORE and TRANSPORT IPC pair and one communicator registration. Its bounded peer table gives each physical session an independently owned socket or retained connect future, engine, ciphertext cursors, send queue and receive credits. Queue, PEERSTORE request and incoming-flow IDs are allocated across the process. Local session generations and service epochs are routing metadata and add no protocol bytes.

Use Communicator::new, admit or admit_connecting, then drive with the original combined process Clock + ReplayHistory port and entropy. Session objects are boxed owners of caller-provided independent backing pools; there are no self-references, leaks, unsafe lifetime extensions or hidden runtimes. The caller supplies the process PILS identity, canonical sockets, listeners, configuration, reconnect attempts and persistent signature monotime. Logical deadline time can regress and is separate from signature monotime.

CREATE requests are retained in a bounded owned queue. Their CreateId capabilities bind the original process, service epoch and request serial. created requires this capability and reports connect-attempt admission, not successful authentication. Shutdown refuses queued and later CREATE requests and finishes existing peers. Service loss retires the old callback epoch; reconnect registers once and reannounces surviving queue identities. A failed or canceled wait never fabricates an application ACK.

Received messages retain their original flow callback until the matching official flow-ID/peer ACK or service failure. Each peer advertises the finite capacity of its reserved waiting-send queue. Its local send continuation admits ACK and then one additive capacity frame exactly once, retaining the original owner between those stages even with a one-frame IPC budget. Neither admission claims remote delivery. Unexpected excess SENDs remain in the bounded original input frame while peer writes and service TX continue; capacity pressure does not report a broken TCP route. Every service direction and each peer's connect/read/write/effect task has a rotating scheduler position.

Terminal native sessions withdraw their queue through one common bounded DOWN
path before clearing unsent requests. Already prepared BOX/ciphertext and active
continuations retain their original core/MAC owner while graceful close drains. A replacement TRANSPORT source reannounces only surviving established queues;
old MIDs, pending result stages and their capacity are never rebound to it.

Replay history is scanned completely before one final REPLACE. Only PS
records and END drive the iterator. The same-source durable local floor is
compared after ReplayStart admission, without creating NEXT/END or callback
credit. Before each original STORE byte string is admitted, the production
ReplayHistory port waits for the bounded ledger worker receipt and the
original frontier minimum-generation durability barrier. Manager retains the
original session generation, PS epoch, scan and STORE callbacks. Queuing is not
persistence or a remote STORE_RESULT. Canceled or uncertain disk work must still
retire its original worker debt; an older late remote REPLACE cannot lower the
local max floor. Actual catalog capacity and failures are explicit, with no
production NoLedger fallback or silent eviction.

The standard product entry is `apps/gnunet-communicator-tcp` (binary
`gnunet-communicator-tcp`), composed with `adapters/tcp-runtime-std`. It uses the
shared PROGRAM/configuration/logger, original PILS/Resolver/services, same
Clock, listener/NAT source owners and paired persistent ProcessPorts. The
runtime performs V2 min0 intent/Unbound1/min1/Bound2 initialization or actual
same-ID complete-catalog recovery, and drains/joins the original worker before
any original Quiescent proof can clean an epoch. V1 is explicitly refused.

Driver remains a one-session facade for controlled component fixtures. The old
`normal_peer` and `normal_multi_peer` example executables have been removed;
their loopback/READY_FILE observation setup and process-local UTC signature
stamps are not alternate production entry points. Use the standard configured
binary for normal process operation. This host crate does not depend on runtime
or provide a fake durable history implementation to keep those old observers
buildable.

Tests retain TCP/Unix I/O, cancellation and clock cases and exercise process/epoch capabilities, simultaneous connect futures, generation retirement and the same-peer scan/store barrier after the original session has physically closed. Actual C multi-peer observations remain separately scoped to communicator/TRANSPORT integration; they do not establish CORE or an independent Rust TRANSPORT service.

The normal runtime consumes that source-recovery API instead of closing its
whole Pool on a shared TRANSPORT I/O loss. `transport_online`, `transport_epoch`
and `transport_reannounced` expose only physical/source/write facts to
that original owner. Address admission refuses an offline MQ, so an unsupported
old effect cannot silently enter a future source. Reannounced observes settled
REGISTER/queue intents and a physically drained current IPC FIFO; it is not a
remote ACK or an ordering barrier ahead of RX. A shutdown manager cannot accept
a replacement TRANSPORT connection. No key, peer stream, prepared ciphertext
cursor, PEERSTORE history or old callback epoch is recreated by attachment.
