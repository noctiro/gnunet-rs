# gnunet-resolver

`gnunet-resolver HOSTNAME` prints every IPv4/IPv6 value returned by the
shared GNUnet Resolver API. `gnunet-resolver -r IP` performs the resolving
reverse operation and prints the returned hostname bytes (or the API's actual
numeric fallback), one value per line. Reverse input is a plain numeric IPv4 or
IPv6 address, without a port or scope extension. No argument is a no-op, matching
the fixed public tool. The package is `gnunet-resolver-command`; its normal binary
name is `gnunet-resolver`.

Standard PROGRAM `-c/-L/-l/-h/-v`, selected Logger/Reporter and testing clock are
reused. One live configuration, RuntimeClock Arc, Broker, original Query
and uniquely owned Driver remain inside the retained original foreground future. Forward uses `Context::ip_get(Family::Any)` and reverse uses `hostname_get(...,
true)`. This executable adds no DNS protocol, OS lookup substitution, resolver
thread, private IPC or epoch-reconstruction path. Standard API local/numeric fast
paths retain their callback semantics.

All queueing, initial retries, query callbacks and stdout backpressure share one
original five-second native/logical budget established before query admission. No reply or retry renews it. Native checks/registers precede canonical/driver
polling. Every Delivery must match the original Query token; its value is
copied into one bounded line before returning the lease, so a slow stdout never
keeps a callback borrowed across another driver poll. Forward port-zero addresses
use bare numeric IPv4/IPv6, consistent with public `GNUNET_a2s` port-zero handling. Reverse bytes retain the C-string callback's bytes without lossy UTF-8
conversion or replacement.

Stdout is the single early borrowed original fd. Actual unbuffered writes are at
most 512 bytes, using zero-timeout readiness plus a 25 ms blocked wakeup and the
original partial cursor. No shared OFD flags, detached reader/writer thread or
untracked task is introduced. A synchronous OS write (including a regular file or
device) cannot be forcibly interrupted by an async timer; readiness is not a
claim of whole-write completion. Reported written bytes count only write
results. Result content only goes to stdout, not Logger/Debug/report.

`[resolver-cli] MAX_RESULTS` defaults to 4096 (1..65536), and MAX_OUTPUT_BYTES defaults to
16777216 (1..67108864). At most one output line is retained, with a maximum of 65536
bytes including newline. The Broker uses 16 bounded request slots and 64 owned-name
slots with the existing native frame bounds. Resource exhaustion is an explicit
failure; rows are not silently truncated. Initial socket retry errors are
retained separately, without pretending they ended a query that later succeeds.

Actual `Complete::End`, non-END completion, cancellation, missing terminal callback,
source loss and physical cleanup remain separate facts. Timeout/source/protocol or
output failure yields a nonzero result, retaining already written prefixes. A
Lost/Unavailable event fences the original query before another native driver
poll: any internal pure reconnect metadata is never used to create a replacement
physical MQ or replay this command's query. Stop cancels the original subscription;
normal pending output/drain may finish only under the same remaining budget. Fatal source/clock/output/Logger failures skip new IO and retire the same owner. Finally the original Query drops, then that Driver disconnects or physically
drops, with independent cancel, Driver, IO, disconnect and Logger causes retained
alongside callback/output metadata. Neither None nor source close is
reported as a successful DNS END. A Logger-only error retains the report.
