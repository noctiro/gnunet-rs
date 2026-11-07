# gnunet-gns-proxy

Standard PROGRAM entry for the bounded Rust SOCKS5 CONNECT and HTTP/HTTPS
proxy. The GNS full-name client selects addresses, LEHO and TCP/port
TLSA records. Only an NotGns outcome admits ordinary DNS through the
same process Resolver; a failed GNS answer is not a DNS fallback. Raw VPN
records use the existing VPN client and retain allocation and cleanup
receipts independently.

The official `-p/--port` defaults to 7777; `-a/--authority` selects an existing
combined CA certificate/private-key PEM. `-6/--disable-ivp6` keeps the official
long-option spelling. `[gns-proxy] BIND_TO`, `BIND_TO6` and `PROXY_CACERT` use
the normal GNUnet configuration and filename expansion. IPv6 settings are not
required when IPv6 is disabled. The optional Rust setting
`[gns-proxy-rust] PKIX_ROOTS` selects a bounded public certificate PEM bundle;
otherwise bundled public PKIX roots are used. The program never installs a
certificate into the operating system or creates an authority file.

HTTP bodies retain streaming backpressure and socket owners. Browser
TLS uses the supplied CA; upstream TLS requires PKIX or authenticated
TLSA validation plus the handshake signature. HTTP Host, Location and
Set-Cookie rewriting retain the selected GNS/LEHO origin boundary. Original
query, connection and native cleanup budgets remain finite; signal, parent
control, logger failure and Resolver cleanup use the original owners.
