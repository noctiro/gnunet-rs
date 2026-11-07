# Bounded HTTP host

This is the concrete HTTP/HTTPS transport mechanically extracted from the HOSTLIST candidate, with GET/HEAD and bounded SOAP POST. HOSTLIST and NAT consume this layer independently. It depends on the existing shared CLIENT Resolver/RuntimeClock/native stream boundary and the already approved Hyper/Rustls/URL stack. There is no HOSTLIST/NAT business dependency, production libgnunet FFI, global provider installation, hidden pool, task, resolver, cookie jar or process owner.

`Instance` is a caller-owned checked Rc allocation domain. `Request::{get,head,soap}` fixes a unique Job, exact URI, absolute logical target, method, safe redirect policy and one shared zeroizing body/action copy. Cloning shares that same immutable intent; `Client::new` allows it to be admitted only once. A new retry/recovery must construct an explicitly new Request. The owner takes an original caller native hard target; all DNS, proxy, TCP, TLS, HTTP and redirects retain the minimum original target. It never reconstructs a deadline from elapsed stages. The borrowed `Client::drive` future may be dropped while the same task/cursor remains in Client. `cancel` physically drops its exclusive connection and preserves original Progress without clock IO.

API:

```text
Client::new(request, shared_resolution, tls, optional_proxy, limits, original_hard)
Client::{poll,drive,poll_observed,cancel,request,progress,hard_deadline,wire,take_diagnostics}
Response { body: Zeroizing<Vec<u8>>, status, head, redirects, wire, diagnostics }
ObservedResponse { response: Response, post_guard: Option<Error> }
Response::job()
Head::{content_length,content_type,location}
```

The original hard alarm is registered before canonical-clock stabilization. Results already returned by the HTTP future are retained during a post-completion clock revision race, never repolled from a completed future. Original network owners close before an error escapes. Capturing a complete HTTP response after a failed original deadline does not manufacture a timely business receipt. Source/Job identities and retained progress are never transferred to replacement IO.

`poll_observed` offers a narrow factual boundary for mutation consumers. Once complete framing has produced the one owned response, it calls a pure borrowed observer exactly once, before any post-response guard can wait or fail. The observer must be selected for that first framing poll; switching from ordinary polling later does not replay the earlier response. The observer may perform bounded classification and retain resulting facts; it must not perform IO, sample clocks, retry or retain the borrow. The same response is retained through a guard wait and then moved with the first post-response guard failure. A later failure or cancellation cannot turn an already classified SOAP rejection or deletion into an unobserved response. Ordinary `poll`/`drive` still return that original error when the post-guard fails; observing bytes never grants permission to continue business work.

`Progress::snapshot` distinguishes bounded owner queue admission, ready-sender dispatch API invocation, nonempty application-write polling, exact outer AsyncWrite plaintext accepted bytes, native socket bytes after dispatch, outer flush observation, response headers and complete entity EOF/HEAD completion. A TLS accepted plaintext count is not TCP acceptance; ciphertext counts do not establish the exact HTTP plaintext prefix. Flush is not a whole-request/remote-processing ACK. Even a failed/Pending opaque stream write may require conservative OutcomeUnknown; `may_have_exposed` therefore includes write attempts. Queueing/dispatch alone is not exposure. Progress has a private constructor and retains its original Job. It is never reset to justify replay. Library-owned pending TLS/Hyper output is destroyed when this exclusive owner closes.

SOAP is always POST with exact quoted SOAPAction, bounded shared body, Content-Type and Content-Length. Its redirect policy is fixed None, including307/308; HTTP errors preserve the bounded status/body so the SOAP consumer can parse a500 fault. There is no automatic HTTP mutation retry. Safe GET/HEAD may explicitly follow at most the configured redirect cap; initial HTTPS cannot downgrade. Cross-origin redirects do not inherit original origin Basic credentials. HEAD exposes selected metadata and allocates no entity body even when its Content-Length describes a large resource. No decompression is silently applied. HTTP/1 framing comes from Hyper, including length/chunked/EOF; cookies and browser behavior are outside this component.

All six configured proxy modes from the original provider remain: HTTP, HTTP1.0, SOCKS4/4a and SOCKS5/local-DNS/hostname. Actual HTTP CONNECT, optional verified HTTPS proxy endpoints and bounded authentication are retained. Shared Resolver address effects are acknowledged only once an connection/proxy target effect is polled. A distinct SOCKS4 IPv4-only lookup capability is explicit. Numeric addresses alone enter native connect; no system-DNS fallback occurs. Physical socket/inner owners drop before their original Resolver connection leases retire. Original native initialization errors/warnings retain their probe ids. Proxy URI scheme/config kind should agree; exotic undocumented libcurl override behavior is not emulated.

The explicit owned Rustls config uses the approved AWS-LC non-FIPS native/asm provider and webpki-roots1.0.11, with hostname/certificate validation, normal SystemTime X509 validity, no client key or insecure verifier, and resumption/early-data disabled. TLS trust time is deliberately separate from RuntimeClock operation deadlines. `Tls::with_roots` accepts explicitly caller-owned trust roots without disabling hostname/validity checks. No pure-Rust-cryptographic-primitive or FIPS claim is made.

Bounds include URI8192, SOAP body1MiB, response16MiB, native64MiB per direction, bounded headers/parser buffers, frames, probes and redirects; profiles can be smaller. URI/body/action retained buffers are zeroizing/redacted. The mature libraries may retain transient parsed URL/header/TLS buffers; their complete wiping is not claimed. `bounded_io` exposes exact byte/expiry guards for an existing accepted-server owner without manufacturing HTTP or business receipts.

Native proxy/TLS behavior, cancellation faults and mixed-service interoperability require central qualification. No new unrelated test matrix or generic HTTP framework is introduced.

A transport failure observed after its connection future completes is returned
with its original cause immediately. Complete response facts and their original
post-guard failure remain separate; ordinary success still requires that guard.
