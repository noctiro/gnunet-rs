# Native host boundaries

This small Unix adapter implements the native hostname conveniences used by
GNUnet v0.29.1 `src/lib/util/resolver_api.c:1149-1255` and the
`GNUNET_OS_get_hostname_max_length` macro in `src/include/gnunet_os_lib.h:389-400`,
at revision `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.

`hostname` performs the native sysconf/gethostname sequence with the official
255-byte fallback. `local_fqdn` implements the `HAVE_GETADDRINFO` branch: native
hostname, NULL service and hints, the first result's canonical name when present,
otherwise the original hostname. It returns an error on native resolution failure. Both return `OsString` and preserve bytes. Diagnostic formatting may be lossy;
the stored hostname and diagnostic fields are not converted to UTF-8.

The adapter calls libc, not libgnunet. Each unsafe operation is individually
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

`addresses::resolve` is the separate explicit-hints boundary used by ARM's
managed listener address selection. It passes raw host bytes and a genuinely
NULL service, copies every result's family/type/protocol/flags and sockaddr,
then frees the successful list through one owner on every exit. A finite result
limit refuses the entire list. `Hints::arm` selects AF_INET when IPv6 is disabled,
otherwise AF_UNSPEC, with type0, IPPROTO_TCP and flags0 as in the pinned source. It does not implement ordinary GNUnet resolver IPC. Numeric family/error/byte
tests run locally; ordinary BINDTO names can still consult native NSS/DNS.

`network::initialize_accepted_stream` applies the source FD_SETSIZE, CLOEXEC,
nonblocking, Darwin NOSIGPIPE and TCP_NODELAY order to a borrowed original fd. It retains at most two nonfatal diagnostics, including warnings preceding a
later fatal error. The owning accepting layer must close on fatal failure. The historical source initializer is retained for its original audit scope. New product accepts use `initialize_reactor_stream`: the same setters, errors
and bounded diagnostics, with no C select/FD_SETSIZE refusal. The shared runtime
accept port closes its uniquely owned stream on fatal initialization and grants
no core admission. Earlier std/mio accept initialization and other OS execution remain explicit
obligations; successful native cases do not prove failed C syscall behavior.
