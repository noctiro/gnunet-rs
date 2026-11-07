# gnunet-uri

Normal PROGRAM default-action dispatcher for one `gnunet://SUBSYSTEM/PAYLOAD`. Shared PROGRAM preparation selects installed/user/explicit configuration,
-c/-L/-l/-h/-v, GNUNET_ARGS and TESTING clock skew. The selected Logger and same
SharedClock feed the Reporter. The unique first-exec inherited parent control
capture remains intact. There is no DNS/MQ query or invented Resolver port.

Both URI and conditional QR frontdoors delegate to `adapters/uri-std`'s
retained Dispatcher; former private child/control/settings modules are
removed. `[uri] SUBSYSTEM` selects executable and arguments via the existing
shared official process command tokenizer. Only that trusted configuration is
parsed. The complete validated URI is appended unchanged as one final argument. Scheme matching is ASCII case-insensitive; configuration owns subsystem matching. URI case, escaping, spaces and non-UTF8 payload are preserved. NUL is refused. There is no shell, automatic `--`, percent rewrite, detached waiter or replay.

This corrects contradictory fixed C call shapes. Its URI producer passes the
whole program as one literal filename, while QR tokenizes program+`--`+URI. The installed namestore mapping is `gnunet-namestore -e 1a -u`, whose CLI requires
`-u` immediately followed by URI. Both Rust paths support those configured
arguments and directly append the URI; neither contradictory C shape is promoted
to a private compatibility requirement. A configuration can explicitly include
an argument separator when that command requires it.

URI handler stdio stays null; QR uses its separate inherited-stdio policy. Parent
control and activation declarations are removed from the child's native
environment. Child spawn/TERM/KILL/wait and selected logging causes remain typed. SIGCHLD only wakes; the original Child.try_wait supplies the ExitStatus. The ordinary URI profile has no new total lifetime. A stop fixes one TERM grace,
then one KILL plus separate cleanup-only wait grace without renewing business
work. Unknown wait authority forbids another raw-PID signal; EINTR does not lose
wait ownership or prove the child remains running.

Explicit clock-free close and Drop attempt the original physical retirement. Only a consuming wait discharges a spawned child's debt. Expired cleanup
without that observation is an undrained failure, never inferred reaping or an
operation ACK. Synchronous OS/provider work may block despite elapsed targets. Exit0 requires handler exit0 and no original/cleanup/logging error. PROGRAM help/version can exit0 without a handler; there is no success stdout.

`[uri-rust]`: MAX_URI_BYTES default65536/max1MiB, MAX_HANDLER_BYTES4096/max65536,
MAX_HANDLER_ARGS256/max4096 (executable included, before URI), STOP_GRACE5s,
positive/max1h per cleanup phase; subsystem cap256bytes. These are local bounds. The desktop handler resource still names the executable; no packaging or
desktop registration is claimed.
