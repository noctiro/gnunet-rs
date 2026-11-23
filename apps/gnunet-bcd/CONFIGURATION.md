# Business-card server configuration

## Listener and tools

All keys below use `[bcd-rust]`. `BIND_TO` defaults to `::` and must be numeric;
`-p/--port` defaults to 8888. The selected bind failure is a startup error.

Set `PDFLATEX` to the absolute path of a TeX Live `pdflatex` executable for PDF
rendering. PNG rendering also requires `GHOSTSCRIPT`, the absolute path of the
Ghostscript executable. Set paths in the deployment configuration. The form
remains available without them; render requests report a missing tool when
needed. TeX uses a fixed template, disables shell escape and automatic mktex
helpers, and stops on errors. Install the template's TeX packages in advance.

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
