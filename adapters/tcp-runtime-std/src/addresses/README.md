# Source-bound TCP candidate publication

`PublishedPool` is a caller-polled runtime composition around one original TCP
`Pool`. It owns no second session engine, TRANSPORT queue, Resolver, task, worker
or clock. `try_adopt` borrows the actual `Listeners`, snapshots the supplied
NAT selector, checks that selector's exact clock Arc against the caller's
`ClockPort::source()`, and prepares every fallible resource before taking a
`Pool` from its original `Option`. That option remains untouched on failure. Adopt immediately after `bind_epoch`, before any address IDs are advertised. The address-ID namespace is exclusively this owner's for that physical MQ;
returning the same Pool after close does not reset that namespace.

The enclosing normal foreground remains responsible for its real initial
PILS/key/TRANSPORT/PEERSTORE acquisition and fair Resolver/session driving. It
uses `pool_mut()` to access only that same original Pool and its exact source
callbacks. Its normal loop must gate new accepts/CREATE work on `is_retiring()`,
fairly poll this owner alongside original `Pool::poll_drive`, Resolver and
shutdown, and retain the owner after an observed failure while cleanup runs. The normal startup keeps this same owner while driving its original Pool and
services. This incremental handoff supplies reversal ports for the matching
Pool/registry/startup integration; it does not contain a second foreground. No fallback discovery implementation is hidden.

Each actual bound family/port comes from `Listeners::addresses()`, including
inherited sockets and the real kernel-selected port for port0. Exact numeric
bindings contribute listener claims. Wildcard bindings expand a real bounded
complete native interface snapshot using each matching family and the original
actual listening port. DOWN, unspecified, multicast and broadcast candidates
are excluded; DISABLE_V6 is honored. IPv6 scope remains in the canonical TCP
address; flow metadata is retained in native registration but omitted from the
public address's canonical key, just as TCP text does not encode it.

The actual official NAT Registration uses those same original native bindings,
protocol TCP6 and section communicator-tcp, requesting ADDRESSES | REVERSAL
callbacks on the same original MQ. It
uses existing AddressWriter/native profiles; there is no extra wire field or
NAT implementation. Every add/remove notification is checked against its
original registration session, epoch and AddressId before updating a claim. Original NAT native bytes stay in the native client; its exact allocation ID is
the reference identity, not normalized IP equality. A held notification remains
held when fixed metadata capacity cannot admit it. Original native deadlines
and TX still progress during that backpressure. No callback or queue result is
interpreted as NAT mapping, UPnP completion, reachability or authentication.

Distinct interface/listener/NAT claims share one canonical address row. Losing a
NAT source removes only that source's claims. An interface or different current
NAT allocation still supporting the same text prevents DEL. Unsupported rows
are withdrawn before fresh rows are offered; their original numeric IDs never
retag a future address. Old DEL admitted to the immutable FIFO stays ahead of
a future ADD. A fresh explicit restart_nat intent is permitted only after the
old source/claims retired and every unsupported old row's DEL was actually
admitted to the original FIFO, with the same captured endpoint and optional
overall deadline. An address still supported by interface/current references
does not block or suffer a redundant withdrawal. It is not replay of any old
mapping/reverse request.

An actual NAT-origin IPv4 address with port0 is retained and published unchanged
as the official behind-NAT reversal hint. It is never treated as a directly
connectable endpoint. IPv6 port0, unspecified, multicast and broadcast addresses
remain excluded. Listener/interface candidates still use their actual nonzero
listening ports; only the actual NAT notification path admits this hint.

`request_reversal(cx, &Reversal, until)` checks the original same-Pool planned
parent and native guard, then submits one original Registration.reverse write. It uses wildcard IPv4 plus an actual IPv4 listener port, and the original remote
IP with port0, matching the official producer. Its non-Clone ReverseWrite holds
that original parent, expected peer, actual NAT session/epoch/write and fixed
finite target. admitted_at is a same-clock sample immediately before actual
local admission; no fallible sample after admission can lose the admitted write. The Pool must synchronously apply this proof once to Planned -> Waiting before
another admission attempt. Later Waiting parents cannot submit another write. Queued/Written/WriteExpired/End retain the original metadata and remain local
facts; no NAT acknowledgement, remote connection or authentication is invented.

`cancel_unexposed_reverse` removes only an actual zero-byte original write. Partial or already-retired/written work is not canceled and never closes the
shared NAT source for one peer. The caller keeps its original unresolved result
and deadline; a replacement source must not replay an uncertain request.

A held Reverse callback generates exactly one ReverseReady view, including its
original session/epoch/ordinal and actual IPv4 remote. The complete native frame
remains inside that same Registration and can be borrowed with reverse_frame.
reverse_notification only checks/registers the existing native guard and views
that callback; it neither reads nor samples a new clock. It remains held while
the real consumer has no connectback slot. Held state does not generate repeated
ready progress, and original native RX/write deadlines continue running. Only
explicit release_reverse of the exact three-coordinate view consumes it, after
the consumer actually admits or refuses the original connectback intent. Native input expiry closes the original MQ first and returns the still-owned
callback in End; no early release, second Registration or private frame exists.

The new callable ports check the same native-only guard before any canonical
sample or new action. A guard-produced original End or WriteExpired is retained
in a bounded slot and delivered by poll before further work; getters and
admission cannot silently drop it. These ports require the separate actual
Pool/registry/source driver integration before end-to-end reversal is available.

All metadata has caller limits. Scan quotas/allocation failures are not partial
snapshots or fabricated removals. Previous interface claims retain only their
original finite freshness, then expire. The owner may have an immutable overall
native/canonical deadline; `Options.until=MAX` omits that total lifetime for a
healthy long-lived communicator. There is no huge finite replacement, periodic
source churn or implicit new registration. Each scan/freshness, initial send,
later native write/input frame and retirement has its own actual finite budget. A finite supplied overall deadline is fixed and never extended by scans,
retries or new registration. The same adjustment subscription remains active. Canonical
clock failure permanently starts clock-free close; actual source/scan errors
remain owned observations. A fixed retry Sleep, source hard, scan target and
claim freshness wake the original caller; there is no perpetual WouldBlock spin.

Every active turn first drives the same Registration native-only guard before
ownerclock/scan/publication, preserving actual original Ended/WriteExpired and
held callback ownership. Ordinary NAT IO, scans and publication use three-way
round robin: neither very short legal scan intervals nor continuous callbacks
can starve another ready class. No fake waiting/progress result substitutes for
actual native IO, and the original deadline is never reset by a guard call.

`AddQueued`/`RemoveQueued` report only successful actual Pool FIFO admission. No local queue is called full socket write, remote application or durable ACK. `begin_close` physically closes the original NAT MQ without needing a clock,
retains its original End, and queues exact old DELs under a finite native grace. `Closed` means those removals were admitted and the NAT owner closed; it does
not mean the Pool drained. `take_pool` then transfers only the original Pool,
including the same admitted removal bytes, so the original caller still drives
actual writes, sessions, quiescence and `ClockPort::finish_epoch`. Grace expiry,
`abort` or Drop physically drops that same Pool and its original MQs; no clean
epoch proof is created and dirty/Unknown backend state remains dirty/Unknown. An independently retained NAT End is delivered before terminal Aborted.

No interface
enumeration, NAT/socket/network, key/crypto/entropy/hash, persistent store/worker,
process/helper/product, Cargo/compiler or model/test path ran. The later
startup call-site composition and actual interoperability qualification remain
explicit work. This is candidate publication, not complete TCP/NAT/TRANSPORT.
