# GNS business-card HTTP host

`Server` owns bounded HTTP connections and renderer jobs. `provider::render`
produces checked PDF/PNG bytes using the fixed public card fields and real native
tools. [Configuration](../../apps/gnunet-bcd/CONFIGURATION.md) describes listener,
tool, directory and resource policy.

## Renderer boundaries

[Template construction](src/provider/template.rs) escapes literal request text;
request fields do not become paths or executable TeX. [Original job directories](src/provider/directory.rs)
create private inputs and log files, bound enumeration and read the actual
post-exit artifact through native file handles. Full file identity, size/change
observations and single-link qualification remain distinct from artifact syntax.

The [process boundary](src/provider/process.rs) selects a narrow platform
leaf. Unix uses the shared launch helper and registry-branded wait ownership.
Windows passes an explicit executable, literal argv, fixed cwd/environment and
private log handles to CreateProcessW. Its registry retains original process and
exit-wait resources. Exit codes retain their platform meaning, including a real
completed Windows code259.

## Retirement and failure

Rendering, stop, native exit, output bytes and directory-name removal are separate
facts in `Report`. An output file or exit0 cannot replace an original exit receipt
or prove application delivery. File-writing failures retain independent writer
close failures. Native child errors retain their original sources.

`RenderFailure::take_retirement` transfers the same unfinished `Retirement` owner
to the server's job slot. Callers keep polling it through actual child reaping
and original directory cleanup. Unresolved jobs keep admission/resource credit.
Unknown wait ownership forbids signaling a reused Unix PID and does not grant
directory removal. Windows termination uses the original process handle.

Application byte/work/deadline bounds exclude opaque child RSS, kernel buffers
and synchronous native-call latency. There is no shell, template selection from
HTTP input, hidden waiter or recursive cleanup of unqualified paths.

Dropping a request future cancels its ticket while Server retains the job.
After `request_shutdown`, continue polling through `Event::Stopped`. Stopped
means no waitable job owner remains; a nonzero `Report::undrained` still requires
failure and does not prove successful cleanup.
