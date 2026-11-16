# Business-card server configuration

## Listener and tools

All keys below use `[bcd-rust]`. `BIND_TO` defaults to `::` and must be numeric;
`-p/--port` defaults to 8888. The selected bind failure is a startup error.

`PDFLATEX` and `GHOSTSCRIPT` select absolute native executables. Unix defaults
are `/usr/bin/pdflatex` and `/usr/bin/gs`; Windows requires explicit paths for the
requested rendering phase. Missing selection is reported by that request rather
than preventing form service. TeX arguments select a fixed template, disable
shell escape and automatic mktex helpers, and stop on errors. Select a compatible
TeX Live installation with the required packages already available.

Unix `LAUNCHER` selects the shared `gnunet-arm-spawn-helper`; its default is the
selected installation's libexec path. Windows creates the selected application
directly and does not use this helper or a command interpreter.

`TEMP_ROOT` defaults to the native temporary directory and must name an existing
ordinary directory. Each job creates a private child: Unix mode 0700 or a Windows
process-user DACL. Administrative namespace changes are excluded while the job
runs. File operations and cleanup retain original native directory/file objects;
metadata observations alone never authorize deleting a replacement.

## Resource and time bounds

| Scope | Keys |
| --- | --- |
| HTTP admission | `CONNECTIONS`, `JOBS`, `HEADER_BYTES`, `HEADERS`, `QUERY_BYTES` |
| Retained input/output | `FIELD_BYTES`, `RETAINED_BYTES`, `REQUEST_BYTES`, `TEX_BYTES`, `OUTPUT_BYTES` |
| Work directory | `LOG_BYTES`, `WORK_FILES`, `WORK_BYTES` |
| HTTP time | `HEAD_TIMEOUT`, `WHOLE_TIMEOUT`, `OUTPUT_TIMEOUT` |
| Child retirement | `CHILD_POLL`, `TERM_GRACE`, `CLEANUP_GRACE` |

Defaults and accepted bounds are defined by the host's [HTTP limits](../../adapters/bcd-std/src/http.rs)
and [renderer limits](../../adapters/bcd-std/src/provider/types.rs). Durations use
standard GNUnet configuration syntax. Original canonical/native deadlines cover
rendering and output; progress never renews permission.

Unix TERM_GRACE precedes SIGKILL. Windows uses TerminateProcess on the original
handle; reports identify that mechanism and retain full unsigned exit codes.
CLEANUP_GRACE bounds foreground retirement observation. Unfinished owned jobs
remain retained for continued cleanup rather than being reported as reaped.
Limits bound application retention and observed job files, not external-tool
RSS/CPU or the duration of a synchronous native filesystem/process call.
