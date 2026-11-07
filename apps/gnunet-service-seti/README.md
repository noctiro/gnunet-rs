# gnunet-service-seti

A standard SERVICE entry for the existing active GNUnet v0.29.1 SETI IPC and
Bloom exchanges over the configured CADET CLIENT. The existing pure
SETI protocol, Server, slot pools, CADET frames and source/operation retirement
algorithms are unchanged.

The shared SERVICE parser supplies `-c/--config`, `-d/--daemonize`,
`-h/--help`, `-L/--log`, `-l/--logfile` and `-v/--version`; `-v` is version. It does not invent a SERVICE `-V/verbose` option. SERVICE's XDG/user/default
configuration policy uses the shared loader rather than PROGRAM's filename
search. `[seti]` supplies endpoints, ACL, USERNAME, Unix credentials and
TOLERANT; `[cadet]` supplies the existing carrier. Existing `[seti-rust]`
resource/time bounds remain unchanged. No private flag migration is added.

The process captures the original inherited descriptors once. Actual daemon
split happens before runtime, account lookup, listeners, native sources or
protocol resources. The parent closes its own inherited copies and waits for
the original startup status; the child refreshes the selected Logger's PID. Within one current-thread runtime, inherited/TCP listeners prepare before USER,
then new Unix listeners finish with the configured match access under the target
identity. Inherited sockets keep their original ownership. All listeners finish
before constructing SETI/CADET resources.

One SharedClock reaches the selected Reporter, the Resolver context and
existing Server source composition. SETI retains its existing CADET
attachment readiness condition. The installed stop stream is checked again
before the READY stdout write and flush; only then is the original
once-only ChildReady signalled. This is local initialization, not remote
operation acceptance or a crypto/store receipt.

SIGINT, SIGTERM or original parent-control stop admissions. A soft stop captures
one native grace target and reuses it; the original alarm is checked before
canonical/Resolver work, even when another class is continuously ready. The
selected Reporter has a permanent failure latch with a same-turn gate before
further normal source work. Logging failure cannot busy-loop on a repeated Stop:
the same Server retires existing work under the original grace and is always
physically closed. No new Resolver IO starts after a logging failure; its
original owner is physically retired without a fresh clock sample.

Every fallible path after Server construction rejoins the same Server.close
finally seam. Actual original errors, independent native cleanup, Resolver
physical disconnect, stdout failure and the original entropy backend cause are
kept separately. First source diagnostic causes are retained in bounded slots;
no payload/key or per-peer diagnostic allocation is added. Branded CADET tickets
are consumed within their scope; static terminal metadata is not a
quiescence proof. STOPPED retains `remote-drain=not-claimed`, and selected
terminal diagnostics do not bypass `-L/-l` through a second fd2 write.

Resource settings and original protocol/source semantics remain documented in
`adapters/seti-std/README.md`. Synchronous OS stdout or
configuration operations are not claimed to be deadline-preemptible.
