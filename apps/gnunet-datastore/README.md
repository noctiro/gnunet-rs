# gnunet-datastore

Standard caller-driven PROGRAM for the configured DATASTORE service. Package name is `gnunet-datastore-command`; its installed binary is
`gnunet-datastore`. `-d/--dump` writes the official binary backup to stdout,
`-i/--insert` reads it from stdin, and `-f/--file` selects an expanded native
filename. With both flags the completed dump is closed first, then insert opens
the same named file (or reads stdin after writing stdout). No positional args or
missing-operation success is accepted. Shared PROGRAM implements `-c/-L/-l`,
default configuration, help/version and GNUNET logging environment policy. This
is not an FS Repository importer/exporter and performs no local hashing or key
operation. It runs under the caller's identity, as the official C command.

The wire-compatible backup starts with exactly16 bytes `GNUNETDATASTORE1`, no
extra NUL. Every record is92 bytes of network-endian metadata followed by value:

| Offset | Bytes | Value |
| --- | --- | --- |
| 0 | 4 | value size |
| 4 | 4 | open block type |
| 8 | 4 | priority |
| 12 | 4 | anonymity |
| 16 | 4 | replication |
| 20 | 8 | absolute expiration micros |
| 28 | 64 | exact datastore key |

Values are bounded by the IPC maximum65535−112=65423 bytes before any
body allocation/read. Bad/truncated magic, partial headers/bodies, oversized
lengths and cursor overflow fail explicitly. Zero-length values are valid. Dump
uses unkeyed ANY/random=false GET from UID0, writes the accepted original
DATA header/body, then requests UID+1. Only true DATA_END terminates; as
in official C, that protocol marker cannot distinguish absence from some backend
errors, and this is not an atomic transactional snapshot. Nonadvancing actual
UID is rejected. PUT uses reservation0 and waits for that original STATUS;
zero and positive status are accepted, negative status aborts. No Unknown/lost
mutation or original request is automatically recreated or replayed.

One caller Slot/ReservationSlot and one retained reply are used. Dump borrows
accepted DATA bytes directly, with no complete value clone. Insert reuses one
Zeroizing65423-byte scratch plus fixed92-byte header; there is no whole-file
collection, VLA or per-record payload allocation. Original request storage is a
Zeroizing65535-byte buffer and the existing native client owns bounded framing
and one retained reply. A small4-slot/256-name-byte shared Resolver with4KiB
frames belongs to the same LiveConfiguration/RuntimeClock Arc as this client. Stored content and opaque status diagnostic bytes never enter Debug logs; a
negative status retains its bounded diagnostic bytes in a redacted Zeroizing
owner. Outcomes/status, record counts and UID remain explicit on failure.

Every record has one original30s logical+native target captured before clock
work. The native alarm is polled before canonical sampling or Resolver/client
polls and never renewed by retries, partial input or backpressure. Reporter
failure wakes/stops the same owned foreground before further work. The shared
PROGRAM foreground helper retains the original future across scheduler failure,
sets its same stop latch and polls it to cleanup; it never substitutes an
empty-success task. SIGINT/SIGTERM and original parent-control signals stop the
owner. Real client close precedes taking any final outcome, keeping Unknown,
NotSent, interruption and an already received STATUS separate. Resolver and
stream close errors remain independent of the original task/logger cause.

Default stdin/stdout use unbuffered native read/write on borrowed descriptors:
no Tokio stdin thread and no change to shared OFD flags. Actual fstat classifies
redirected regular files. Other streams use zero-timeout poll(2), finite10ms
readiness cadence and the same Stop/deadline/Resolver loop. WouldBlock/EINTR do
not create a busy retry. Nonregular writes are at most512 bytes, the POSIX
minimum PIPE_BUF. Readiness is advisory: competing users can race it. Explicit
regular-file/open/metadata/flush/close calls retain their synchronous OS blocking
contract and cannot be force-preempted; guards run before and after transfers. No false hard-interrupt guarantee is made. Owned File close is consumed once,
including uncertain EINTR, with no fd-number retry. Borrowed stdin/stdout are
never closed. Failed/partial output is left explicit; it is not rolled back or
called a complete backup. File write/close is not an fsync/durable-store claim.
