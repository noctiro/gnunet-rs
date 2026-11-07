# Normal four-participant CONSENSUS public-API caller

`consensus_client.c` links the unchanged official CONSENSUS, CORE,
TRANSPORT application and util libraries. It uses `GNUNET_PROGRAM_run`
configuration and starts no service.
With four separately supervised normal participants ready, launch one actual
compiled caller per participant:

```
/ABS/consensus_client -c /ABS/node.conf -L ERROR ROLE PID0_52 PID1_52 PID2_52 PID3_52 SID_HEX128 START_US DEADLINE_US
```

`ROLE` is exactly `0` through `3`. All callers receive the same four distinct
current public identities in the same role order, the same complete
64-byte SID as 128 hexadecimal characters (no `0x`), and the same original
absolute start/deadline in decimal GNUnet microseconds. Its public CORE
startup callback must independently match the supplied local role's identity.
Start must still be in the future, deadline must follow start and be no more
than 180 seconds ahead at admission. A usable planned window is start at
now +40 seconds and deadline at start +130 seconds. Actual launch delays must
still leave every caller time to establish its peer prerequisites, finish its
two insert callbacks and call conclude before the unchanged start.

Before opening CONSENSUS, the caller registers public TRANSPORT application
interests for the other three supplied peers. Each `INTEREST` is local admission
only. It opens public CORE with an empty message-handler table, sends no TEST
payload, validates the startup identity and records each remote
`CORE_CONNECT`. The API's synthetic self connection has a separate `CORE_SELF`
event and does not count as a remote peer. Only when the other three peers are
simultaneously live does one deferred task emit `CORE_READY`, create CONSENSUS
and emit `SESSION_OPEN ... admission=local-API-only`. Service startup alone is
insufficient. A remote disconnect before session creation may recover before
the original start; source loss or any peer loss after creation fails. CORE and
all original interest/application handles stay owned until cleanup. This profile
requires the separately prepared direct peer topology and does not add a DHT
service or address-discovery fallback.

Each role sequentially inserts the same public 16-byte common value and its
own distinct public 16-byte value from the source's fixed tables. Both use
type0. The next insert and conclude are deferred until the preceding actual
InsertDone callback returns. `CLIENT_QUEUE_HANDOFF ... assurance=local-API-only`
records that callback only: it is not a service ACK, an IPC-write proof or
remote agreement. The pinned official API omits the INSERT type assignment and
the RECEIVED type byte-order conversion; this type0 profile avoids those
limitations without patching official C. It does not qualify nonzero types.

Every received callback compares all 16 bytes and its type/length against the
expected role values. Local own/common, NULL, malformed or unknown elements
fail. The API may repeat another role's exact value: these callbacks are
deduplicated and counted in `END`, without unbounded duplicate log output.
The Conclude callback must see exactly all three other roles' values.
Partial collections do not pass. That callback destroys the official MQ but
leaves its Handle owned by the caller; scheduler shutdown and Handle destroy
are deferred until after the callback returns.

One native 200-second elapsed-time alarm starts before PROGRAM preparation and
is never renewed. The original absolute start/deadline tasks and boundary checks
also remain unchanged. The pinned API's MQ error handler only logs and does not
deliver NULL to the application, so these deadlines are necessary even when no
error callback arrives. Native expiry requests ordinary scheduler SIGTERM
cleanup. An external supervisor must still enforce its original process target,
stop uninterruptible calls and consume every exit; no callback, insert,
reconnect or stage grants a fresh budget.

For each role, success requires one matching `OPEN`, four matching `PEER` lines,
three matching local-only `INTEREST` events, one matched `INITIALIZED`, actual
CORE connection observations for the other three peers with no subsequent
loss during the session, and one each of `CORE_READY` and `SESSION_OPEN`,
the two ordered `CLIENT_QUEUE_HANDOFF` events (`common`, then `own`), one
`CONCLUDE_SUBMITTED ... before-original-start=yes`, exactly one matching
`ELEMENT` for each other role, one `CONCLUDED ... unique=3 expected=3 matched=yes`,
and `END role=R passed=yes handoffs=2 unique=3 duplicates=N concluded=yes reason=complete`,
plus that original caller's exit0. Four participants must independently
satisfy this predicate. Timeout, missing callback, late conclude, external stop
or output failure is failure. This is a normal C public-API component, not a C
peer algorithm, a failed-participant profile or a build/runtime receipt.
