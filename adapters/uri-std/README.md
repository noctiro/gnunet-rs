# Shared URI handler owner

`Settings::read`, `from_uri` and `from_qr_uri` select a configured GNUnet URI
handler. [Configuration](../../apps/gnunet-uri/CONFIGURATION.md) defines command
parsing, native encoding and resource limits. The selector preserves one complete
URI argument; decoded symbols never choose executable code outside that policy.

## Child ownership

`Dispatcher` retains one staged operation and one original child across dropped
`drive` futures. Unix uses its exclusively wait-owned child and SIGCHLD hints.
Windows uses an original native process handle and a kernel threadpool exit wait,
without a per-child polling worker. Windows application selection, argv quoting,
environment and cwd use the shared native process interface; batch files cannot
implicitly dispatch through a shell.

URI child stdio is null; QR inherits stdio. Parent control, activation and detach
bootstrap declarations are removed from the child's environment. Original parent
control and native termination subscriptions stay attached to the dispatcher.
A hint or wake never proves that a child exited.

## Deadlines and retirement

QR's original canonical and native targets cover acquisition, scanning and
handler dispatch. Guard checks precede spawn and follow actual exit observation;
a late exit0 remains late. Neither progress nor cleanup renews business time.

Unix first stop sends SIGTERM; Windows uses TerminateProcess on the original
handle. Reports identify the mechanism. One fixed stop grace precedes forced
termination, followed by a separate cleanup-only grace for exit observation.
Unknown Unix wait ownership forbids later PID signaling. Native signal/parent,
clock, diagnostic, stop, force-stop and wait failures retain their typed sources.

`close` and Drop perform clock-free original-child cleanup attempts. Callers
inspect `CloseReport` independently of `drive` failure. A spawned child without
an actual exit observation is undrained; dropping the owner cannot prove reaping.
Synchronous native creation, stop and filesystem calls are not preemptible.
