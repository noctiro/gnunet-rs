# Shared URI handler owner

`Settings::read`, `from_uri` and `from_qr_uri` select `[uri] SUBSYSTEM` for a
validated case-insensitive `gnunet://SUBSYSTEM/...` prefix. The shared existing
`service_runtime::process::parse_command` parses only the trusted configured
program. The executable receives its configured arguments followed immediately
by the complete original URI as one argument. URI case, escaping, non-UTF8 bytes
and spaces are preserved. NUL is rejected. There is no shell, URI tokenization,
implicit argument separator, percent rewrite or duplicate command parser.

The fixed C sources disagree in this area. `gnunet-uri.c` uses literal
`run_command_va`, while `gnunet-qr.c` tokenizes `program + " -- " + uri`. The installed `namestore.conf.in` ends the program with `-u`, and the installed
NAMESTORE CLI requires `-u` to consume the immediately following URI. Treating
the program as one filename or inserting `--` there prevents that normal import. Both Rust frontdoors therefore share parsed configuration arguments and append
just the original URI. A configured command can explicitly contain `--` when its
own argument grammar requires it. These are concrete public behavior corrections,
not a claimed reproduction of those contradictory C call shapes.

`Dispatcher` retains one staged operation and actual `std::process::Child` across
dropped observation futures. It owns the original parent control, signals,
selected Reporter and shared clock. QR supplies one original canonical/native
whole bound across acquisition, scan and dispatch; ordinary URI retains its
existing profile without a new total lifetime. Guard checks precede spawn
and follow the consuming exit observation. An observed late exit0 does not
become timely success. A child exit is an OS fact, not a service processing ACK.

URI handler stdio is null; QR handler stdio is inherited, matching their original
C producer policies. The parent control/activation environment declarations are
removed from the child without transferring their owned descriptors. A real
TERM starts cleanup; one fixed grace permits ordinary exit, then one KILL and a
separate fixed cleanup-only grace observe the same child. The original operation
is never renewed. Unknown wait ownership forbids raw-PID signalling. EINTR keeps
wait ownership without authorizing a signal from an unobserved running state.

Explicit `close` and Drop are clock-free original-child cleanup attempts. Independent TERM, KILL, wait and business causes survive. Actual consuming wait
is required before `undrained` can be false for a spawned child. Expired cleanup
or a dropped owner cannot promise reaping; residual debt is a failure. Native
spawn/signal/filesystem/provider calls can block in the OS and are not made
preemptible by a target. No hidden process, waiter task or replay exists.

`[uri-rust]` bounds: MAX_URI_BYTES default65536/max1MiB,
MAX_HANDLER_BYTES default4096/max65536, MAX_HANDLER_ARGS default256/max4096
(including executable, before the one URI argument), STOP_GRACE default5s,
positive/max1h for each cleanup phase. These are deployment limits, not protocol
fields.
