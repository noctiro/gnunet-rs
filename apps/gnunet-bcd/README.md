# Normal GNS business-card server

`gnunet-bcd -p 8888` is the normal PROGRAM frontdoor. Standard configuration,
log selection, shared clock, original inherited parent control and SIGINT/TERM
precede the numeric TCP listener. READY logging means the HTTP
listener and bounded owners exist, not that any rendering tool has run. The
program rejects unexpected inherited listener descriptors after really retiring
them; it does not impersonate SERVICE socket activation.

GET `/` and `/full` show independent simple/full forms with the thirteen public
card fields, typed GNS public key, optional nickname and OpenPGP fingerprint. The submit paths generate a PDF business card; presence of `gnspng` asks
for the QR-only PNG even on the full route. HEAD returns simple-form headers
without generating an artifact. Tools are not loaded or executed at startup. Provider absence or rendering/conversion failure is a HTTP500, with no
fallback picture or false completion.

`[bcd-rust]` has numeric `BIND_TO` (default `::`). IPv6 listeners explicitly
disable `IPV6_V6ONLY`; configured IPv4 uses a IPv4 socket. A failed selected
bind or unavailable family is a startup error, with no hidden interface
fallback. `PDFLATEX` and `GHOSTSCRIPT`
default to `/usr/bin/pdflatex` and `/usr/bin/gs`. `LAUNCHER` selects the actual
shared GNUnet spawn helper; the default comes from the selected installation's
libexec path. Each may be overridden with an absolute configured path. Missing
Ghostscript is irrelevant to PDF-only requests. `TEMP_ROOT` defaults to the
existing native temporary directory; an override selects an existing parent. Each original job creates a distinct private child directory and removes it after child
retirement. There is no arbitrary template, shell command, shell escape or
implicit renderer installation.

Bounded configuration keys are `CONNECTIONS`, `JOBS`, `HEADER_BYTES`, `HEADERS`,
`QUERY_BYTES`, `FIELD_BYTES`, `RETAINED_BYTES`, `HEAD_TIMEOUT`, `WHOLE_TIMEOUT`,
`OUTPUT_TIMEOUT`, `REQUEST_BYTES`, `TEX_BYTES`, `OUTPUT_BYTES`, `LOG_BYTES`,
`WORK_FILES`, `WORK_BYTES`, `CHILD_POLL`, `TERM_GRACE` and `CLEANUP_GRACE`. Time values use the existing GNUnet configuration syntax. Defaults are in the
host's public limit types. The full original HTTP lifetime caps renderer and
response writing; retries and cleanup cannot renew business permission.

On stop, sockets close first and every independent original rendering
job is canceled and drained. The program keeps wait ownership if the OS has not
reaped a still-owned child; it never calls that state clean or frees the job quota. If the original wait right is irrecoverably lost, or directory cleanup ends unsuccessfully after reaping, the original error/path and undrained report remain. Admission stops, other waitable jobs drain, and the program exits with failure; no reused PID is signaled or unproven directory removed. External
tool CPU/RSS and filesystem blocking have the explicit limits described in the
host README. This implementation adds the conditional BCD product only; it does
not prove whole GNS/GNUnet or provider deployment qualification.
