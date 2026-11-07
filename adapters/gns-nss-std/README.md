# GNU libc GNS host-name integration

This adapter supplies the GNU NSS host-address boundary over the existing
GNS/IDENTITY IPC clients. It does not load production `libgnunet`, invoke the GNS
CLI, create a permanent worker, or substitute a host DNS result for a GNS answer. An IDENTITY missing-suffix result is `NotGns`; GNS source failure and an
zero-address GNS answer are different outcomes.

On Linux with GNU libc, the library exports `gethostbyname_r`,
`gethostbyname2_r`, and `gethostbyaddr_r` under each of `_nss_gns_`, `_nss_gns4_`,
and `_nss_gns6_`. The normal and IPv4 profiles default AF_UNSPEC to IPv4; the IPv6
profile defaults to IPv6. Restricted profiles reject the other family. Reverse
lookup is explicitly unavailable, matching the official installed NSS module. This is the OS boundary, not a new GNS protocol or a claim that musl/macOS has the
same plugin interface.

## Loader artifact and administrator configuration

Cargo's cdylib artifact is `libnss_gns.so`. GNU libc loads versioned names:

| nsswitch source | Installed loader name | Exported hook prefix |
| --- | --- | --- |
| `gns` | `libnss_gns.so.2` | `_nss_gns_` |
| `gns4` | `libnss_gns4.so.2` | `_nss_gns4_` |
| `gns6` | `libnss_gns6.so.2` | `_nss_gns6_` |

A package installer must copy the GNU target artifact as `libnss_gns.so.2` to
that system's NSS library directory and install `libnss_gns4.so.2` and
`libnss_gns6.so.2` as aliases/symlinks to it. All nine hook symbols are in the same
DSO; no second native implementation is required. The GNU-only build script sets
its ELF SONAME to `libnss_gns.so.2`. Merely building the unversioned Cargo artifact
does not install or activate it. The administrator may select `gns`, `gns4`, or
`gns6` in the existing `hosts:` nsswitch chain. Ordering and NSS action policy are
administrator choices. This implementation installs nothing and changes no OS file.

## lookup and resource ownership

The default whole-call cooperative budget is five seconds, captured before
starting the worker. Each accepted call creates one scoped, joined OS thread and
one current-thread Tokio runtime; it never enters an existing caller runtime. There are at most sixteen admitted calls per loaded DSO/process and a 512 KiB
worker stack. Capacity pressure returns TRYAGAIN/EAGAIN before starting another
worker. Bookkeeping uses one PID-branded atomic word and a PID-branded thread
reentry guard. A child process does not inherit fictitious active-worker counts,
MQs, runtimes, private keys, or a global lock held by another worker.

This does not make NSS async-signal-safe. Invocation after a multithreaded fork
before exec has the ordinary POSIX limitations of allocation, libc and thread
creation. There is no claim of a safe arbitrary at-fork callback. Every call
checks real/effective UID/GID and bypasses root and privilege-transition callers;
the official module also bypasses root.

Configuration follows normal PROGRAM filename discovery and installed defaults. Each call has a private snapshot. GNS/IDENTITY CLIENT endpoints retain their
configured Unix paths and TCP HOSTNAME/PORT values. Unix-first/fallback
selection remains in the original CLIENT owner. Literal IP and reserved
`localhost` callbacks use the same broker. Only exact configured GNS/IDENTITY TCP
endpoint names may use the private OS bootstrap port; no user GNS query name can
reach this port or ordinary DNS. Configuration and GNS suffix mappings are not
rewritten.

For a selected ordinary endpoint hostname, the worker calls synchronous
OS `ToSocketAddrs` with numeric port zero. Its PID-branded reentry latch remains
set throughout this call. A normal synchronous libc NSS callback into any of this
DSO's nine hooks therefore returns UNAVAIL before starting another worker. The
system's existing non-GNS NSS modules can supply the endpoint addresses according
to its normal nsswitch action policy. An administrator policy that terminates on
UNAVAIL can instead refuse bootstrap; this adapter does not change that policy.

The whole returned address list is collected before handing any address
to CLIENT. It is limited to 32 native address entries and 1024 bytes of retained
native socket-address storage, with fixed inline storage. Overflow is a real
capacity error, not a truncated successful END. IPv4/IPv6 order, duplicates,
interface scopes and flow information from the OS are preserved. The explicit
CLIENT socket-address callback starts the TCP probe after replacing only
the configured service port. An IP-only observer refuses a result with nonzero
scope/flow rather than silently discarding its metadata. Both callback methods
share one offered slot, acknowledgement cursor and original connection lease. Successful enumeration gives the normal CLIENT owner socket candidates;
its callback acknowledgement/connection lease remains tied to this exact list. Only a socket connection is a connection result. Empty address enumeration
and OS errors are not fabricated GNS answers.

The original native hard is checked immediately after the synchronous OS call,
before collecting or publishing any address, and throughout collection and
callbacks. A late OS error keeps both its original IO cause and the elapsed-hard
fact. A late successful OS result is rejected, with no new connection effect. OS resolver internals are not under this adapter's allocator/thread control; the
adapter's retained address/input limits do not claim to bound libc's temporary
getaddrinfo allocation. There is no detached resolver task or second runtime.

DNS compatibility uses the existing complete DNS/IDNA public conversion. The
original C input remains the returned `hostent.h_name`; address data comes only
from the requested A/AAAA records in the original GNS answer. At most
sixteen addresses are retained. Supplementary record types are not mislabeled as
IP bytes. Malformed address data is an error. All aliases, name, address bytes
and the NULL-terminated address pointer table live in caller-provided memory,
with checked absolute-address alignment and full layout capacity preflight. ERANGE returns TRYAGAIN without a partially committed hostent.

One SharedClock Arc and one explicit Resolver broker serve the GNS and
IDENTITY clients. The original native and canonical targets cover routing and
all lookup phases. No retry renews them. Native expiry checks precede canonical
clock waits. Completion/cancellation physically closes the original dedicated
clients; finally the same Resolver disconnect is attempted and the driver
is dropped. The runtime is then dropped and the original worker joined. The safe
Rust API keeps owned independent query/close/driver causes and these facts. The GNU hook maps them to NSS status/errno/h_errno without logging caller data.

The five-second target is cooperative. Synchronous configuration filesystem reads,
OS endpoint DNS resolution, IDNA/key conversion inside existing dependencies and
native runtime teardown cannot be force-preempted safely. A call can therefore return after five seconds;
it still joins its original worker rather than detaching it or claiming a timeout
proves retirement. No new effect is admitted after a checked expired target. There is no automatic ARM startup, host DNS fallback, fabricated negative result,
or timeout-based proof of remote request completion.

## References

The external hooks, family policy, sixteen-address limit, root bypass, original
name and five-second default follow fixed GNUnet v0.29.1
`src/service/gns/nss/{nss_gns.c,nss_gns_query.c,nss_gns_query.h,meson.build}`. GNU status values and `hostent` are taken from the public GNU libc `nss.h` and
`netdb.h`; Rust reuses `libc::hostent`. Direct IPC and joined scoped workers replace
C's CLI fork/exec implementation. Typed native failure is preserved instead of
copying its unused timeout-return branch or shell-based service restart.

The GNU cross toolchain linked an ELF64 x86-64 shared library; static
inspection confirmed SONAME `libnss_gns.so.2` and all nine required hook exports. The library was not loaded or installed. Runtime NSS lookup, mixed-node
interoperation and key/crypto execution remain unperformed; compilation and ELF
inspection do not establish runtime interoperability.

The ordinary endpoint hostname bootstrap successor also passes selected
macOS/Linux strict compilation and GNU shared-library linking. The prior
SONAME/export inspection applies to its unchanged ABI and link-directive inputs;
it was not repeated.
