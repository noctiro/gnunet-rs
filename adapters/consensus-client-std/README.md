# Native CONSENSUS caller

This caller uses the original official520 JOIN,521 INSERT,524 CONCLUDE and
523 element/525 done frames on one configured CLIENT MQ. It creates no
service, background worker, hidden Resolver, private ACK or peer protocol. The selector configuration is frozen once; its supplied shared clock and actual
Resolver remain caller-owned ports. Construction reserves a clock listener
but native connection/timer work occurs only while explicitly polled.

Client::new(source, Join, Limits, Bounds), insert(type,data), conclude(),
poll_progress(cx)/progress(), native_deadline(), poll_native_guard(cx), close(). Insertions may be admitted before JOIN writes. JOIN, each original INSERT and
CONCLUDE remain in an ordered FIFO, each with a distinct original local token
and fixed write bound. Written is whole local write, not service
processing, durability or peer acceptance. Cancel-safe progress waits retain
the same request bytes/cursor and never resubmit them on a replacement MQ.

The public JOIN deadline clamps the caller's unchanged logical/native bound. Setup, original write and partial-input phases have finite hard targets; partial
bytes never renew them. A single lazy native alarm tracks the earliest target. Normal IO checks the same shared clock; closing and the hard fence are clock-free. Pre-attachment socket retry has no mutation exposure and remains within the
original hard. Once an MQ is lost it is physically closed and cannot reconnect.

After attachment, RX and TX are polled fairly on the same original MQ. A caller paused after whole JOIN/INSERT and before CONCLUDE still observes real
EOF or read/protocol errors; an output queue or a pending native write cannot
hide that loss behind its later original deadline. Ready classes alternate and
both directions are polled when one is pending. Every IO turn rechecks the same
original source, native and canonical bounds. Before physical retirement the retained input prefix is snapshotted from
Framed, including a malformed header that failed before a positive read-progress
event. Prefix accounting and FIFO write
receipts retain their original meaning; no receive event acknowledges a write. A complete premature response, including525 before the original whole524, is a
protocol refusal and physical loss, never Done. Real523 remains independently
owned when its source later retires, and no replacement MQ/replay is introduced.

Only real525 after the original whole CONCLUDE yields Done. EOF, source failure,
protocol error, timeout or explicit destroy yields Loss with the epoch,
original cause, whole JOIN/CONCLUDE facts, insertion-write count and every
unfinished original request's independent prefix/whole/bound metadata. Loss
reporting moves the already owned FIFO after physical retirement and allocates
no new request list. There is no invented cancellation frame or failure ACK. The caller retains already delivered receipts and each pre-attach Retry.

Official public callbacks exclude values inserted locally. This SDK records
bounded typed SHA512 fingerprints of admitted own values and suppresses matching
523 values, including the fixed C service's otherwise returned own type0 values. It preserves the complete raw response for selected remote observations. Fixed C ordinary INSERT always produces type0 and its nonzero receiver type
conversion differs; no nonzero-type C interoperability has been established.

Queue frame/byte limits, own-fingerprint count and SDK payload/metadata
capacities are explicit. Common Framed has its separate finite RX frame and TX
queue policy; these limits are not an RSS measurement or a whole-process peak
guarantee. One complete response is copied only when handed to the caller,
which then owns that output allocation. No whole result batch is accumulated.

Dependencies: gnunet-client-host, gnunet-service-runtime, gnunet-wire,
gnunet-types, gnunet-crypto (own-value fingerprints only), tokio rt/time. No CLI is added because fixed C installs no ordinary CONSENSUS CLI.

The duplex source forward includes prepared native Unix-source cases for EOF
and malformed input while paused before CONCLUDE, Pending native INSERT
FIFO pressure with original prefix/bound/unknown disposition preservation, a
premature525 refusal, and an owned523 surviving real525/source retirement after
whole524. These are local native failure/ownership fixtures, not peer agreement
producers or successful CONSENSUS qualification.

Dropping an original Client also uses the existing clock-free physical-close
path, retiring its public Epoch before the native Channel storage is dropped. Caller-held receipt/observation Epoch clones therefore become non-live when
that exact MQ is destroyed. Drop creates no Done/Loss callback, ACK, replay or
replacement source.
