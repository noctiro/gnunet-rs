# Native host boundaries

This adapter implements native socket and hostname boundaries. Unix hostname
behavior follows
GNUnet v0.29.1 `src/lib/util/resolver_api.c:1149-1255` and the
`GNUNET_OS_get_hostname_max_length` macro in `src/include/gnunet_os_lib.h:389-400`,
at revision `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.

## Hostnames and name resolution

On Unix, `hostname` performs the native sysconf/gethostname sequence with the official
255-byte fallback. `local_fqdn` implements the `HAVE_GETADDRINFO` branch: native
hostname, NULL service and hints, the first result's canonical name when present,
otherwise the original hostname. It returns an error on native resolution failure. Both return `OsString` and preserve native bytes. Diagnostic formatting may be lossy;
the stored hostname and diagnostic fields are not converted to UTF-8.

On Windows, `hostname` uses `GetHostNameW`; `local_fqdn` uses `GetAddrInfoW`
with null service/hints and the same first-canonical-name fallback. UTF-16
is preserved in `OsString`. Each call owns a successful Winsock startup reference
and releases it after its native result owner. No environment hostname fallback
is used.

The adapter calls native OS APIs, not libgnunet. Each unsafe operation is individually
scoped with its pointer, initialization and lifetime argument. A private RAII
owner releases the successful getaddrinfo allocation exactly once, including
early errors. No foreign pointers are exposed by the public API. Core protocol
libraries and the IPC adapter continue to forbid unsafe code.

The synchronous FQDN helper can block and use native NSS/mDNS/DNS. Ordinary
GNUnet forward and reverse requests use the official resolver IPC and must not
call this helper as their implementation. Native build profiles using the older
gethostbyname2/gethostbyname alternatives remain pending.

`cargo test -p gnunet-native --locked` exercises the native hostname and
numeric getaddrinfo components. These tests do not issue a lookup for the host's
hostname, alter host configuration, or certify all native NSS profiles. Positive combined FQDN interoperability still needs an isolated native resolver
environment; the separate resolver owner tracks that acceptance gap.

## Unix address snapshots

`addresses::resolve` is the separate explicit-hints boundary used by ARM's
managed listener address selection. It passes raw host bytes and a genuinely
NULL service, copies every result's family/type/protocol/flags and sockaddr,
then frees the successful list through one owner on every exit. A finite result
limit refuses the entire list. `Hints::arm` selects AF_INET when IPv6 is disabled,
otherwise AF_UNSPEC, with type0, IPPROTO_TCP and flags0 as in the pinned source. It does not implement ordinary GNUnet resolver IPC. Numeric family/error/byte
tests run locally; ordinary BINDTO names can still consult native NSS/DNS.

## Socket initialization

`network::initialize_accepted_stream` applies the official source initialization
policy to a borrowed original socket. `initialize_reactor_stream` uses the same
native setters without the C select descriptor-number limit. The borrow neither
accepts, closes nor substitutes the socket. At most two ordered nonfatal
diagnostics are retained; fatal failure preserves earlier diagnostics and the
original native error. The accepting owner closes the socket on fatal refusal.

Unix uses descriptor inheritance/nonblocking flags, Darwin NOSIGPIPE and TCP
NODELAY. Windows uses handle inheritance control, Winsock FIONBIO and TCP_NODELAY.
`set_exclusive_address_use` selects Windows SO_EXCLUSIVEADDRUSE before a service
listener binds. This avoids mapping Unix address-reuse policy onto Windows.

## Windows identities

`identity::process_user` reads the primary-token user through a uniquely owned
TOKEN_QUERY handle. `identity::account_sid` resolves a native account name through
LookupAccountNameW. Both return validated, fixed-capacity SID owners; no Unix
numeric identity, environment fallback or privilege change is introduced. Account
names and referenced domains have explicit UTF-16 bounds. Native lookup failures
retain their Win32 error. Process SIDs do not authenticate TCP peers.

## Verification and constraints

`cargo xtask verify runtime` runs real sockets and shared framing/CLIENT/Resolver
TCP scenarios on the native host. Native hostname tests do not resolve the host's
own name or change system configuration. FQDN interoperability still requires a
controlled native resolver environment. Platform gaps remain in
[implementation status](../../IMPLEMENTATION_STATUS.md).
