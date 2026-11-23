# Ordinary GNS web proxy

This adapter supplies a SOCKS5 CONNECT proxy for GNS HTTP and HTTPS. Numeric requests select their original IP; domain requests
use the full-name GNS owner with its IDENTITY suffix lookup. Only a real
NotGns outcome permits ordinary DNS through the original process broker. GNS
source errors and genuine empty Answers never become DNS fallback. Actual
GNS A/AAAA, LEHO and matching TCP+port BOX/TLSA records select the upstream. Raw VPN records are a proxy consumer extension: an original USE_IP callback
must allocate an address before it can enter the plan. UDP VPN records do not
represent a TCP CONNECT target and are omitted explicitly.

## Public interface

SOCKS greeting/request reads preserve following HTTP/ClientHello bytes. Bound
listener addresses come from sockets; one failed bind remains observable
while another family works. Port443 and matched TLSA service records select TLS. The browser hostname remains the original SOCKS authority. LEHO supplies the
upstream SNI/Host. HTTP1 request/response bodies and trailers stream through real
Hyper connections under backpressure, with bounded headers and no maximum-body
preallocation. Each request owns a fresh upstream HTTP connection and is never
replayed after request exposure. Location, Access-Control-Allow-Origin and
matching Set-Cookie domains are rewritten back to the browser authority with
hostname boundaries; lookalike hostname prefixes are not rewritten. Upgrades
and nested HTTP CONNECT are explicitly refused, not silently passed as raw data.

Local HTTPS requires an explicit configured combined CA certificate/private-key
PEM. The authority checks certificate constraints and loads an issuer only
after its private key matches the CA public key. The issuer signs a DNS or IP
SAN certificate for the browser connection. The operator manages browser trust.
Both TLS directions use the
[shared Rust provider](../tls-crypto-std/README.md). Upstream TLS uses rustls
CertificateVerify and either PKIX hostname verification or selected GNS TLSA/DANE. TLSA
supports usages 0–3, selectors 0–1 and matching types 0–2. It compares the
original certificate or public-key DER directly or via the shared SHA-256 and
SHA-512 helpers. Unusable associations are reported and skipped. A set with no
usable associations uses ordinary PKIX. A mismatch among usable associations
remains fatal. Usage 2/0/0 can supply an omitted CA from the association.
Configured public PEM roots join Mozilla anchors;
retained full DER is needed for usage0 hashed full-certificate root associations
when the server omits that root. No trust-store mutation or libgnunet FFI exists. Session certificate resolver guards, exact service/hostname binding and original
expiry stay live; resumption/early data are disabled and ALPN is HTTP/1.1.

Runtime takes caller-supplied Sources/Ports and creates no broker/task. All
selectors share the same Clock Arc and original Resolver Context. Startup guard
is used only for bind preparation. Each accepted session captures a fresh
finite whole-session budget (default300s); GNS, DNS, VPN, connect, crypto and HTTP
phases reuse its unchanged targets. Default single-operation GNS/IDENTITY/VPN
profiles retain required reply/debt capacity without allocating64 rows per
session. GNS configuration mapping is shared read-only across sessions. Body
buffers grow only with stream traffic. Diagnostic metadata is separate
from IO authority and original native byte counts are separate from body yields.

Stop/timeout/Reporter failure drives finally paths. A once-captured
cleanup native hard (default5s) is shared across old HTTP/TLS leases and sockets,
with no canonical-clock dependency or renewed grace. Local GNS/IDENTITY owners
physically close; ordinary Resolver subscriptions revoke only their original
callback, leaving shared wire debt with the foreground's one Driver. VPN close
preserves LocalUnsent/Unknown/submission independently of allocation and
never claims remote lease revocation. HTTP retains old IO until shutdown
or explicit bounded failure. The original FD is relinquished promptly when its
unique IO lease ends, so old requests do not retain128 FDs until session end. Whole SOCKS writes, body EOS, TLS authentication, shutdown and physical local
retirement are distinct observations. No Drop or timeout is renamed remote
success. Runtime Closed is its local listener/session scope; the foreground must
still disconnect/drop the same original Resolver Driver.

The [proxy command](../../apps/gnunet-gns-proxy/README.md) and
[CA preparation command](../../apps/gnunet-gns-proxy-setup-ca/README.md) compose
this host with native startup and configuration.
