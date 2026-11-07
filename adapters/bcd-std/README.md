# GNS business-card HTTP owner

This is the normal BCD product consumer. It serves GET `/` and `/full`,
GET `/submit/simple` and `/submit/full`, and the official dedicated HEAD response
(200 with simple-form metadata and no renderer). Other methods return 501;
unknown GET routes return 404; invalid typed GNS keys/forms return 400. `gnspng`
presence selects PNG irrespective of its value; otherwise a PDF is
returned. Attachments use `gns-qr-code.png` / `gns-business-card.pdf` and the
corresponding `image/png` / `application/pdf` MIME types. A missing or failed
renderer yields 500 for that request. Static forms and HEAD need no render tool.

The thirteen original fields, optional OpenPGP fingerprint and nickname are
bounded and decoded once from the GET query. The shared `ZoneKey` parser checks
the standard typed zone public key. The QR contains the original validated key
text and the once-decoded nickname in `gnunet://gns/KEY/NICK`. There is no extra
percent encoding, Unicode normalization or second decode. Text is escaped only
for display. The fixed provider reads the URI as data, not TeX source. HTML and
TeX layouts are independent MPL implementations; no GPL templates are bundled.

`Server::new(listener, renderer, clock, limits)` adopts an listener and
one shared process clock. `poll` drives bounded HTTP/1 connection futures and a
separate bounded renderer-job pool without spawning tasks. Each connection has
one request and closes after its response; this does not reproduce C's internal
keepalive queue. Original head/whole/output canonical and native bounds gate
socket IO. A socket completion reports only local HTTP writing,
never remote consumption. Read/write prefixes and independent typed close
causes remain observable on normal errors and shutdown.

A Hyper request future owns only a ticket. Dropping it signals cancellation;
the independent Server job retains its original process, directory, bounds and
wait rights until cleanup. A provider failure with unresolved retirement
retains the same job slot and continues polling its opaque original owner; it
does not release quota or claim cleanup from a timeout. Irrecoverable wait-right loss or terminal directory cleanup failure instead produces the original undrained report and retained path, stops admission, and cancels/drains every other waitable job. This is fatal and never counted as clean retirement. `request_shutdown`
closes admission/sockets and requests every original job's stop. Continue
`poll` until `Event::Stopped` before dropping Server; `Stopped` means no waitable owner remains, and a nonzero `Report::undrained` still requires failure. A progress wait may be
dropped while the Server remains owned; it does not restart a renderer.

Limits bound headers, query fields, active connections/jobs, application-owned
output and provider reservations. Aggregate admission includes every possible
connection output and every active renderer reservation. These are application
buffer/slot budgets, not a measured RSS guarantee for Hyper, the allocator, OS
or an external TeX/Ghostscript process. Native filesystem calls and providers
cannot be forcibly preempted by a cooperative clock check; unknown OS cleanup
remains explicit rather than becoming a successful render. A genuinely still-owned unreaped child retains its slot; terminal lost ownership or directory failure is a fatal unconfirmed outcome, never an indefinitely resumable wait.

Runtime/provider/deployment/interoperability qualification is
not inferred from the source implementation.
