# gnunet-nse

Official installed command name `gnunet-nse` (Rust package `gnunet-nse-command` avoids the already existing pure NSE crate name). `-m, --monitor` monitors NSE estimates; default prints the first estimate and closes. Shared PROGRAM configuration/log/help/version options are retained; positional arguments are rejected.

Output: server UTC timestamp, `#peers=2^logestimate`, `ld(#peers)=logestimate`, `stddev=deviation`, with six decimal places. NaN/inf are preserved as statistical observations, not a verified count. No PoW, private key or NSE daemon runs in this command. Original native source and output deadlines, partial cursors, finite backpressure, signals and shared Resolver/clock are owned by gnunet-nse-client-host.

Local resource configuration example is in nse-client.conf. The default first-result budget is60s; -m monitors until signal unless MONITOR_TIMEOUT is explicitly configured. Every original source has finite INIT/partial/lifetime bounds. stdout is conventional synchronous stdio with one bounded original line; no inherited descriptor/status flags change. Synchronous write/flush OS duration remains an explicit blocking boundary, not a hard-cancellable network operation.

Business, connection and Resolver diagnostics use the one PROGRAM-selected
Logger and SharedClock, honoring `-L/-l`; estimate lines remain functional stdout. A selected-log failure wakes the original subscriber and stops it through actual
source close and Resolver disconnect before returning. The first logging error
is retained separately from the command and cleanup errors. A Resolver owner is
established before task submission, so rejected or canceled scheduler tasks also
retain their original disconnect error without a second cleanup attempt.

Source presence and selected compiler checks do not establish native,
model, crypto/PoW/key, recovery or official interoperability acceptance.
