# Native platform adapter API

This adapter implements native socket, hostname, identity and filesystem boundaries. Unix hostname
behavior follows
GNUnet v0.29.1 `src/lib/util/resolver_api.c:1149-1255` and the
`GNUNET_OS_get_hostname_max_length` macro in `src/include/gnunet_os_lib.h:389-400`,
at revision `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.

## Windows packet capture

The [WinDivert boundary](WINDIVERT.md) owns an explicitly selected installed
provider, original filter handles and bounded overlapped packet loans. DNS
capture policy remains in the DNS host; the native module defines no protocol.

## Darwin PF states

The [PF boundary](PF.md) owns a complete bounded state snapshot, exact local DNS
flow selectors and original-ID readback under one native deadline. The DNS host
retains PF rule, interface and journal ownership.

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

## Interface snapshots and datagrams

`interfaces::snapshot` copies bounded native unicast address rows using Unix
`getifaddrs` or Windows `GetAdaptersAddresses`. `InterfaceState` keeps POSIX flags
separate from Windows adapter type, operational status and per-address DAD state.
Addresses preserve native indices, IPv6 scopes and prefix/netmask information.
On macOS, iOS and FreeBSD, each IP row takes its index from the matching
`AF_LINK` record in the same `getifaddrs` list. Missing or conflicting link
indices leave the row's index at zero.
`is_usable` requires an up interface and, on Windows, preferred/deprecated DAD.
Invalid records or exceeded bounds fail the complete snapshot.

Windows interface and DNS projections share an initialized aligned native buffer
with bounded growth and checked record/pointer extents. No enumeration performs
DNS queries or mutates interfaces.
`network::isolated_datagram_receive_error` and `socket_family_unavailable` retain
native error classification. Windows UDP TTL-expiration reports remain isolated
receive errors with their original code, without attributing a peer or retiring
the shared socket. Windows UDP setup disables ICMP port-unreachable
receive resets on the original socket; that control grants no send receipt.

`network::LocalReplyPath` binds a received UDP datagram to its original listener,
peer, local destination and ingress. A reply uses that local source and the
observed zone when either endpoint is IPv6 link-local. Linux and macOS use
packet information, FreeBSD supplies IPv4 destination and ingress separately,
and Windows uses provider-specific `WSARecvMsg` and `WSASendMsg` on the original
registered socket. An invalid path or source-selection failure returns an error.

On Windows, `interfaces::Identity` observes the LUID, GUID, index and calling
thread's network compartment. Revalidation selects the original LUID and rejects
changed identity or compartment. WinDivert reply routes and Wintun administration
share this observation; only Wintun's actual adapter owner grants administrative
authority. A successful observation does not pin an interface through a later
kernel operation. The boundary uses Microsoft's [GetIfEntry2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getifentry2).
Capture observations, interface retirement and vacancy checks share one owned
complete [IP Helper table](src/interfaces/table.rs), with row bounds checked
before borrowing its native array. WinDivert retains at most two immutable
capture-time views; its [routing contract](WINDIVERT.md#packet-metadata-and-injection)
separates those observations from kernel interface ownership.

## Native address resolution and readiness

`addresses::resolve` copies complete native results with exact family/type/
protocol/flags, a NULL service, original result ordering and native canonical
names. `Hints::arm(Families)` chooses AF_INET or AF_UNSPEC before resolution.
Unix uses getaddrinfo; Windows uses scoped Winsock startup and
[GetAddrInfoW](https://learn.microsoft.com/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfow).
Capacity, malformed input and unsupported families never return a partial list.
Numeric-only tests avoid ordinary DNS traffic.

`network::socket_readiness` borrows one original socket for a zero-timeout poll
or WSAPoll. Read/write, hangup and exceptional flags remain distinct. It neither
consumes bytes/backlog nor changes shared notification state. `is_listener`
observes the original listen role. Darwin uses the SDK-qualified libproc socket
prefix; other Unix hosts and Windows query their native socket option.

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

`network::unix_address_layout` supplies native family/structure sizes for local
diagnostics, including Windows SDK sockaddr_un bounds. It grants no socket or
credential capability. Windows `ipv6_text` uses bounded numeric `InetNtopW` without
DNS, socket creation or WSAStartup. Native output remains ASCII and errors retain
their Winsock code. See the [numeric conversion contract](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-inetntopw).

## Windows local socket observations

`local_socket` queries the original borrowed AF_UNIX local/peer address,
SO_ACCEPTCONN state and connected peer PID through
[`SIO_AF_UNIX_GETPEERPID`](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/shared/afunix.h).
It validates native lengths and family, decodes native UTF-8
names without substitution, and preserves unnamed endpoints and Winsock errors.
The caller retains the socket and its Winsock lifetime. No filesystem lookup,
handle transfer, process-token lookup or peer authentication occurs. Nonblocking
connect-status helpers classify original Winsock errors without granting success.

## Windows identities

`identity::process_account_name` resolves the actual primary-token SID through
bounded native account-name storage. It does not trust the USERNAME environment
or manufacture a Unix identity; native name lookup can block or fail.

`identity::process_user` reads the primary-token user through a uniquely owned
TOKEN_QUERY handle. `identity::account_sid` resolves a native account name through
LookupAccountNameW. Both return validated, fixed-capacity SID owners; no Unix
numeric identity, environment fallback or privilege change is introduced. Account
names and referenced domains have explicit UTF-16 bounds. Native lookup failures
retain their Win32 error. Process SIDs do not authenticate TCP peers.
`identity::process_primary_group` observes the token's actual primary group SID
without inventing a POSIX GID or authenticating a local socket peer.

## Windows TUN devices

The [Wintun boundary](WINTUN.md) retains an explicit trusted provider, original
GUID/LUID/index, adapter and fixed-capacity session. Whole native packet loans
retire inside each call. Native interface/address/route operations and actual DAD
observations remain separate from packet and remote-processing results.

## Unix command leases

`process::inherit_file` adds an owned duplicate of an original file description
to a `std::process::Command`. The child clears only that duplicate's close-on-exec
flag; parent descriptors retain their flags. The duplicate is above standard IO
and shares the original file lock. The selected executable must retain it until
guarded work finishes. The API returns neither a descriptor number nor a child
readiness observation.

The DNS PF controller uses this boundary so a surviving control command keeps
its lease after helper death. New recovery remains fenced until the original
command releases that file description. Process exit and durable policy
retirement remain separate observations.

On macOS/FreeBSD, `process::EffectiveUser` captures a setup-time effective UID
for a selected child. Its pre-exec credential syscall leaves the parent's identity,
real UID and groups unchanged. The kernel still requires inherited real/saved
credentials; the value grants no privilege. DNS uses this only for the fixed
trusted PF control executable, with cleared environment and bounded arguments,
while its packet pump remains under the reduced UID. Spawn failure retains the
credential error; native saved-root execution requires separate qualification.

## Windows process ownership

`process::Spawn` launches an absolute executable with an independent argv0,
literal UTF-16 arguments, explicit environment/cwd and selected standard handles.
Windows CRT quoting preserves empty arguments, quotes, backslashes and isolated
UTF-16 units. Native case-insensitive ordinal ordering resolves environment names;
generated handle exports override explicit values. No implicit shell or PATH
lookup is used. Only private copies in the CreateProcessW handle allowlist inherit.
Callers exclude concurrent legacy launches with unrestricted handle inheritance
during that operation. Original caller handles and process-global state stay owned
by their callers.

`process::Process` retains the original process HANDLE. Nonblocking status checks
confirm termination before reading the full unsigned code, including 259.
`ProcessWait` uses native threadpool notification, disassociating before invoking
caller Wake code. Cancellation retains notification memory until callbacks return
without waiting for the child or holding its handle through arbitrary Wake code.
Forced termination is an explicit request, not an exit or readiness receipt.
See the [runtime process contract](../service-runtime/PROCESS.md) for registry
credit, original-child identity and cancellation.

## Windows directory observations

`paths::exists` queries native final-node attributes, including AF_UNIX reparse
nodes. It grants no access or liveness authority. `paths::system_directory` owns
the native GetSystemDirectoryW result without an environment fallback.

`paths::internet_database_directory` reads Windows' configured `DatabasePath`
using [RegGetValueW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-reggetvaluew).
It expands REG_EXPAND_SZ through the native wide API and preserves REG_SZ
literally. Only an absent key/value selects the system directory's `drivers/etc`;
access errors, wrong types, malformed/relative strings and resource limits remain
errors. UTF-16 paths retain unpaired surrogates. Queries and expansion each have
three attempts and a 32768-unit ceiling. Resolver hosts and GNS protocol/services
files share this observation; querying does not open or authenticate a directory.

## Windows DNS configuration

`dns::servers` takes a bounded synchronous GetAdaptersAddresses snapshot of
operational adapters. It preserves native API order, IPv4/IPv6 addresses, ports
and IPv6 scopes, deduplicating exact tuples. A link-local address lacking a scope
uses its actual adapter's IPv6 interface index. Native records and pointers stay
inside one initialized aligned allocation; traversal, buffer growth and result
counts are bounded. Invalid output or capacity exhaustion fails without returning
a partial snapshot. No DNS query or background refresh is performed. This is a
startup/explicit-refresh input, not Windows NRPT or per-query routing emulation.

`dns::configuration` reuses one adapter snapshot for server and suffix
projections. Its primary DNS domain comes from
[GetComputerNameExW](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getcomputernameexw);
a genuinely empty primary domain permits the first nonempty operational-adapter
suffix. `SearchDomain` retains the selected primary/interface origin, both native
IPv4/IPv6 interface indices and valid Unicode text. Query errors and malformed or oversized strings remain errors;
they never become an observed empty domain. Server and domain results retain
independent errors, so an optional suffix failure does not discard valid servers.
Growth, native extents and UTF-16 conversion are bounded by `Limits`. This single
GNUnet domain selection does not emulate Windows search lists or devolution.

## Anchored filesystem operations

`filesystem::publication::publish` stages private bytes under a held directory,
synchronizes and explicitly closes their writer, then applies the caller's
original selection/deadline fence. `Create` refuses replacement. Windows moves
the original stage to the target in one native no-replace rename. FreeBSD uses
`renameat2` with `AT_RENAME_NOREPLACE` when available. Other Unix paths use
exclusive linking followed by removal of the stage name.
`Replace` requires caller-authorized namespace administration. Finalization
synchronizes the directory when available. When unavailable, it flushes the
original at its published name and returns `DirectorySync::Unavailable`. A
returned read lease owns the actual published object. Failures retain stage,
possible publication, original writer-close error and identity-checked temporary
cleanup without retrying an uncertain unlink. This shared mechanism backs REST
credentials and CONFIG output.

`filesystem::Directory` owns an original directory on Unix and Windows. Child
opens, private creation, no-replace linking and checked removal use that held
directory rather than rebuilding full paths. Unix callers serialize namespace
administration across identity checks and POSIX name-based link/unlink requests.
Windows publication/deletion acts on captured original objects. `sync` reports
`DirectorySync` independently of data-file synchronization.

`PrivateFileSnapshot` checks the selected name and the held private file
against a previously verified byte snapshot. Use `confirm_read` with metadata
captured before reading to finish capturing the snapshot. If FreeBSD UFS
changes only ctime after publication, confirmation and later checks require
bounded SHA-256 readback from the same file, with stable metadata and a matching
name, before caching the new timestamp.

On Windows, `Directory::sync` qualifies the original handle's volume as local
NTFS and reopens that same directory with `FILE_ADD_FILE` access. If access is
denied, it retries with `FILE_ADD_SUBDIRECTORY` access. Either lease can request
the normal `NtFlushBuffersFileEx` barrier. A completed flush reports
`Synchronized`. Other filesystems and access or sharing rules that exclude the
writable lease report `Unavailable`. Other open and flush errors retain the
native cause.
[MS-FSA directory flush](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/0de7dc40-9627-437e-a4df-c4696cdc3d02) · [Windows filesystem behavior](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/4e3695bd-7574-4f24-a223-b4679c065b63) · [NtFlushBuffersFileEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntflushbuffersfileex)

General directory owners permit compatible metadata mutation. The explicit
`open_source`, `from_source_file` and `open_source_directory` constructors retain
Windows source sharing fences; source hosts use these constructors. Such a fence
refuses generic-write directory opens but does not make children immutable or
replace caller-controlled namespace exclusion.

`replace_file` checks the original single-link source and atomically replaces a
child name. Unix uses anchored `renameat`; Windows captures the source link and
uses [native rename information](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)
relative to the held target directory. Existing target handles retain their old
objects. Mutation owners allow write sharing needed by Windows's internal target
open; source owners retain their stricter sharing policy. No copy or pathname
fallback exists. An error can follow visible replacement, so callers preserve
uncertainty and synchronize data/names separately.

`publish_directory` installs a prepared original sibling at an absent name;
`remove_directory` retires only an empty directory matching its held original.
Linux, macOS, and FreeBSD with `renameat2` use kernel no-replacement rename.
Windows captures and renames the original directory handle without replacement.
On FreeBSD, an independent original parent descriptor serializes publication and
removal. Kernels without `renameat2` check for absence while holding that lock.
Callers still exclude administrative namespace races. `AlreadyExists` means
unpublished; other errors can follow publication.
Neither operation performs recursive cleanup or a synchronization barrier.

`entries` owns an independent cursor over the original directory: Unix uses a
separate open description; Windows uses original-handle enumeration with a
reused aligned 4 KiB buffer. Names remain native `OsString` values, including
unpaired Windows UTF-16 surrogates. Query/record errors remain errors; a zero
next-record offset only ends the current batch. Collection limits, sorting and
source revalidation belong to the caller.

`entry_info` observes a child without following name surrogates or reading data;
`file_info` observes an already held object. `FileIdentity` preserves Unix
device/inode or the complete Windows volume/128-bit file ID. Its tagged local
encoding is an observation, not original-object authority or a wire format.

`FileTimes` retains native modification/change fences without access-time noise.
Unix callers can reuse one metadata snapshot; Windows reads actual original-handle
basic information. Values use the native epoch and are compared within the same
identity, not as portable wall-clock timestamps.

`FileReader` provides positional reads without moving the caller's cursor. Unix
uses `pread`; Windows reopens the same original object with a private file pointer.
Exact reads retain native errors and reject premature EOF.
`validate_readonly` checks original granted data-write access, not ACL ownership
or content immutability.

`private_single_file_identity` qualifies a regular private file with exactly one
hard link, returning its complete native identity. Unix checks effective ownership
and permission bits in one metadata observation; Windows checks token ownership,
the restrictive DACL and the original handle's link count. Callers still exclude
administrative replacement and revalidate their selected directory entries.

`private_data_file_info` additionally qualifies a readable data file and returns
its length and native change fences. Unix excludes executable and special mode
bits; Windows retains its native ownership/DACL policy. Qualification never
changes the file's permissions, link count or selected name.

`ExclusiveFile` owns the original physical lock file. It uses the standard
[nonblocking native lock](https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock),
preserves contention and native errors, and releases its handle on drop without
unlinking the name. Unix locks are advisory; Windows locks also constrain data
access. Borrowing the original file does not grant permission to clone, unlock
or replace an application's lock owner.

Windows `ReadMapping` owns an unnamed read-only original-file section and view.
It exposes a raw address for trusted synchronous native consumers, without a Rust
slice or a whole-file heap copy. The section pins the ordinary truncation boundary;
concurrent data changes and native in-page exceptions remain possible. Explicit
close unmaps before releasing the section and retains failed views for retry.
See [Windows mapping semantics](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)
and [mapped-file truncation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setendoffile).

## Windows file security

`local_path::prepare_parents` creates protected directories for AF_UNIX endpoints
and checks the final existing parent's owner and mutation grants. It preserves
existing ACLs and refuses unsupported ACE forms. `LocalPath::inspect` returns an
`ObservedLocalPath` without automatic deletion or an ACL-setting API; `capture`
owns best-effort Drop cleanup for a newly owned node. `set_access` sets that
original node's owner and DACL before listen. `remove` reopens the original file object for DELETE and applies
extended POSIX disposition. Sharing/volume failures remain observable and retain
the handle for retry; no removal operation resolves a replacement pathname.
The service runtime owns bind, stale-probe, socket-close and cleanup ordering.
Callers exclude concurrent namespace/ACL changes and thread impersonation during
startup. These ACLs control endpoint access but do not establish peer identity.

`paths::profile_directory` queries the process-token user's profile through
GetUserProfileDirectoryW with a finite UTF-16 bound. It neither opens that
directory nor substitutes an environment or registry guess. `open_directory`
uses native directory-open flags, checks metadata on the owned handle and
requests traverse access plus optional read/list access.

`identity::file_owner` reads the owner SID from the original opened file or
directory handle; a subsequent pathname lookup is not used. READ_CONTROL is
required and errors remain explicit. Ownership is a time-local observation,
not an authorization decision.

The `paths` facade separates lossless encoding (`paths/encoding.rs`), directory
operations (`paths/directory.rs`), native system/profile discovery
(`paths/discovery.rs`) and file admission/publication (`paths/file.rs`). Callers
use the facade; raw handles and UTF-16 buffers remain inside the native adapter.

`paths::Directory` holds an original directory independently of later renames.
Its single-component child operations preserve native UTF-16, reject traversal
and alternate streams, and refuse name-surrogate and AF_UNIX file entries.
Private creation installs a protected process-user DACL at creation; existing
private directories require actual owner/DACL qualification. Explicit source
directory handles deny competing generic-write opens. File identities compare complete native
volume/file IDs and remain observations, never cleanup authority by themselves.
Hard-link publication uses the original file object and refuses replacement;
explicit removal checks a captured link against the still-held original before
applying native disposition. Blocking I/O and provider/sharing errors remain
observable. These operations do not supply a directory synchronization barrier.
See Microsoft's [relative file opening](https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntcreatefile)
and [hard-link information](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_link_information)
contracts.

`paths::create_directory_all` resolves the native absolute path once and creates
missing ancestors iteratively. Borrowed prefixes avoid recursive stack growth or
copies of each complete parent name. Existing directories succeed; blocking files
and native errors remain failures. Permissions follow native inheritance. This
operation is not a transaction or an authorization lease, and a later failure can
leave created parents. File opens still enforce their actual requested access.

`paths::create_private_file` creates a new noninheritable disk-file handle with
a protected DACL granting only the process-token user full control. Existing
names and alternate data streams are refused; streams cannot have independent
private permissions. The caller owns writing, syncing and closing that file.
`publish_file` selects explicit `Publication::Create` or `Replace`: creation
refuses an existing destination; replacement uses ReplaceFileW with destination
ACL/metadata merging and retains merge errors. Both accept native Unicode and
bounded long paths. A failed replacement can have changed the namespace; callers
must inspect both names and preserve any surviving prepared file. No automatic
fallback drops the destination ACL. Publication alone does not guarantee
parent-directory crash durability.

## Locale readers

`locale` shares comparison selection, bounded C-string views and typed conversion
results. POSIX and Windows backends own their native handles separately.
`LocaleSnapshot` is immutable and shared through `Arc`; only its last owner frees
the allocation. Named snapshots never install a locale. Native conversion reports
consumption and range failure independently, including signed zero and overflow.

Windows uses UCRT `_create_locale`, `_get_current_locale`, `_free_locale` and
explicit-locale comparison/conversion functions. Configuration floats use a
private C locale and validate the remaining whitespace; formatting uses native
bounded `%f`. Neither operation changes the thread or process locale, including
failure and late TLS destruction. CRT errno is preserved and is kept distinct
from Win32 error numbers. See Microsoft's [locale creation](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/create-locale-wcreate-locale)
and [ownership](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/free-locale)
contracts.

## Windows regular-expression locale

`locale::regex::Locale` owns an immutable CRT classification snapshot and, for
named collation, the system ICU collators and contraction set. C collation is
ordinal. BMP classification uses `_iswctype_l`; supplementary scalars use NLS
character data. The adapter supplies classification, full/primary comparison,
actual collating-element membership and maximum element width; regex syntax
and matching stay in the PROGRAM layer.

Named collation loads the absolute system-directory `icu.dll` on Windows 10
1903 and later. Versions 1703–1809 use the documented `icuin.dll`/`icuuc.dll`
layout, with a same-thread COM reference matching the current MTA or STA model.
Both S_OK and S_FALSE initialization references are balanced after native objects
close. An existing combined provider's load/export failure never falls back.

Provider modules are pinned for process lifetime to retain native cache/TLS code;
individual collators and sets still close with their owners. No library search,
download or locale mutation is performed. ICU/CLDR sorting data can differ from
NLS and other platform data.

Validated NLS category names select ICU by full language tag, including cultures
without a unique LCID. Legacy alternate-sort names use the exact LCID mapping.
ICU parent-data inheritance is permitted; changing the selected language/script
or requested alternate sort is refused. Contraction inventory is bounded to 16384 items, 128
UTF-16 units and 64 Unicode scalars per string. A compact first-scalar width
index bounds candidate scans without a native lookup. Native errors retain their domain.
See [Windows ICU](https://learn.microsoft.com/en-us/windows/win32/intl/international-components-for-unicode--icu-)
and the [ICU collation API](https://unicode-org.github.io/icu-docs/apidoc/released/icu4c/ucol_8h.html).

## Native library references

`library::Library::load` requires caller-trusted native code, dependencies and
loader state. It accepts absolute paths. Unix selects `RTLD_NOW | RTLD_LOCAL`;
Windows selects the DLL directory plus System32 without changing global search
settings. Loader redirection and already loaded modules remain part of the trust
contract. Symbol addresses and library-owned storage stay within the owning
thread's live reference. `close` attempts release once and rejects later symbol
queries; success does not imply physical unloading. Drop is best effort.

Windows `pin_for_process` uses the original module address to retain that mapping
until process termination. It is irreversible; the owner's original loader
reference still closes normally. Providers without a background-work join API,
including [Wintun](WINTUN.md), pin before dispatching foreign work. Pinning does
not observe callback completion or resource removal.

`load_basename` explicitly admits Unix basename lookup through the trusted
process loader search paths. It rejects path components and retains the same
thread-local ownership and ABI contract as absolute-path loading.

Windows errors retain their Win32 codes. POSIX errors carry `library::Diagnostic`
with an immediate lossless prefix capped at 1 KiB and explicit truncation state.

## Windows calendars

`calendar::Calendar` combines checked Gregorian arithmetic with native UTF-16
formatting. Numeric calendar fields cover the complete GNUnet microsecond domain;
the UCRT epoch range does not narrow protocol timestamps. `format_in` borrows an
immutable locale;
`format` uses the current native thread locale. Neither installs a locale or
changes system time. Native return codes retain their CRT domain.

UTC `%z` and `%Z` are emitted explicitly because UCRT's `tm` contains no per-value
zone fields. Local calendars retain the UCRT fast path for ordinary dates. Outside
its epoch range, explicit Microsoft TZ or Windows dynamic-year metadata supplies
validated offsets and daylight transitions. Historical metadata is selected by
local year; recurring boundary rules extend beyond the installed year table.
Windows fold/gap policy chooses daylight bias in a repeated hour and standard
bias in a skipped hour. Expanded values keep their real calendar/ISO week year;
only locale name rendering uses an equivalent valid native formatting view.
Localized `%c`/`%x` outside 1900..9999 return Unsupported instead of a false
year. Formats
use the documented UCRT vocabulary, including `#`; invalid codes are refused
before the native invalid-parameter handler can run. Output has an explicit
UTF-16 capacity, supports empty expansions and retains native code units. See
Microsoft's [calendar conversion](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/gmtime-s-gmtime32-s-gmtime64-s)
and [wide formatting](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strftime-wcsftime-strftime-l-wcsftime-l)
contracts. See the [native test matrix](../../tests/README.md#continuous-integration).

`calendar::DateParser` retains LC_TIME names and an immutable CRT locale snapshot
under the caller's native-locale mutation exclusion. Parsing accepts complete ISO
dates, localized ctime names, and Windows OLE locale dates. ISO omitted month/day
mean January/first day. Native names resolve through public NLS APIs, including
legacy UCRT language/country names; no CRT private layout is inspected. Month and
weekday matching uses the retained exact name with
[FindNLSStringEx](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-findnlsstringex).
Cultures with a unique LCID use OLE Automation. Supplemental cultures use named
NLS short/long date and long/short time pictures for the selected calendar.
Non-Gregorian components retain their era and calendar month until dynamically
resolved Kernel32 calendar APIs convert them to Gregorian fields. A complete
calendar roundtrip rejects normalized invalid dates and dates outside their
stated era. Native metadata supplies historical era names, Japanese first-year
text and the two-digit year window. Month names include genitive forms and a
thirteenth month; Hebrew named-month slots are adjusted for the actual year's
leap-month layout. Hebrew date numerals retain their native omitted-thousands
convention, while other Unicode digits use NLS folding. Names use linguistic
source-span matching. Enumeration, allocations and total matching work are bounded.
No user-default culture or different calendar provider is substituted when the
selected native API is unavailable. Supplemental picture/name data is retained on
the first successful load and shared by parser clones; OLE observes regional
settings at parse time. See the
[named date enumeration](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumdateformatsexex)
and [calendar metadata](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getcalendarinfoex)
contracts and Microsoft's dynamically resolved
[calendar conversion](https://learn.microsoft.com/en-us/windows/win32/intl/convertcaldatetimetosystemtime)
API. Native calendar availability and date ranges follow the installed Windows
provider.

UTC arithmetic and expanded ISO years preserve signed epochs and the full
GNUnet microsecond domain. Local conversion extends `_mktime64`'s range using
the same checked fields and explicit timezone selection. Parsing never changes
locale, TZ,
system time or validation handlers. Malformed ISO fields are refused before
native normalization. Bounded UTF-16 inputs reject NUL and trailing ISO text;
OLE failures preserve `AutomationDateError`'s original HRESULT separately from
Win32 and CRT errno. The standalone `windows_date_parser` test isolates locale/TZ
changes in fresh children. See Microsoft's [date parser](https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-vardatefromstr)
and [local conversion](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/mktime-mktime32-mktime64)
contracts, Windows [year-specific timezone metadata](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-gettimezoneinformationforyear)
and [transition rules](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/ns-timezoneapi-time_zone_information).

The POSIX current-thread capability installs an owned numeric-C locale only for
the conversion call. Its guard restores the previous selection before freeing
the temporary locale, including on lexical failure. Its unsafe acquisition
contract requires external native-locale mutation/lifetime exclusion. The same
exclusion protects Windows current-thread observations, which expose no raw
locale pointer or installation authority. Native tests check selection identity
on success and failure, retained snapshots and conversion during thread exit.

## Local command and path bytes

`os_bytes` preserves Unix bytes and Windows UTF-16 code units for local byte-based
parsers. Unicode uses UTF-8; isolated Windows surrogates use canonical WTF-8.
Ordinary Unicode strings and Unix native bytes are borrowed. Decoding uses safe
native string constructors and rejects malformed or noncanonical Windows input.
NUL is preserved so the final OS/C-string boundary can apply its own policy.
This representation does not change GNUnet message or text encodings.

`os_bytes::strip_ascii_prefix` borrows a native option suffix without allocation
or Unicode conversion. It accepts only ASCII prefixes and preserves isolated
Windows surrogates. The split stays at a boundary permitted by the
[standard OsStr contract](https://doc.rust-lang.org/std/ffi/struct.OsStr.html#method.from_encoded_bytes_unchecked);
it never decodes external or persisted bytes through an unchecked constructor.

## Process standard streams

`stdio::stdin_file` and `stdout_file` capture owned native duplicates for binary
I/O on Unix and Windows. They preserve redirected bytes without global buffered
stream locks, CRT conversion or shared Unix flag changes. Coordinate concurrent
stream users and capture stdin before buffered reads. The caller owns blocking
execution and retirement; [PROGRAM binary I/O](../program-std/BINARY_IO.md)
provides that composition. `filesystem::close` consumes a file and returns its
single native close result without retrying a reused descriptor or handle.

`stdio::stdin_ready` queries the original route without consuming bytes or
changing shared flags: Unix polls the descriptor; Windows peeks a pipe and leaves
other routes to the original reader. Windows `cancel_synchronous_read` targets a
retained worker HANDLE. Its request result remains separate from the actual
canceled read status and original file close; a missing pending operation may
require a later bounded request on that same worker.

`stdio::Output` duplicates the original stdout route. File/pipe writes retain
bytes; console writes use bounded UTF-16 conversion and preserve complete Unicode
scalar boundaries. A later process-table replacement cannot retarget the writer.
It uses no Rust global stdout lock and can block in the OS; callers explicitly
offload it and retain its handle/buffer through actual completion. Output flush
is not a filesystem durability barrier. Capture/console/write errors stay errors.

`stdio::Stdio` defines explicit inherit, closed, NUL and borrowed-handle child
inputs, also reexported by `process`. `PreparedStderr` snapshots a detached
destination without changing parent streams: file/pipe objects receive owned
duplicates, character devices select NUL and absent stderr stays closed. Child
creation borrows that retained selection instead of rereading a mutable table.

`stdio::ProcessStderr` requires unsafe acquisition under process-wide standard-stream
quiescence. Installation duplicates a borrowed file independently for Win32 stderr
and UCRT fd2. Original-file and capability drops leave both destinations live.
One process-owned Win32 handle is retained and replaced on the next successful
publication; CRT fd2 owns a separate handle. GetStdHandle returns a borrow, not
permission to close or adopt that owner. The Win32 destination is inheritable;
CRT byte output is binary, with no newline translation.

Preparation lifts private CRT descriptors above all three standard slots and
restores their Win32 table values, including independently valid native streams
whose CRT slots were closed. CRT replacement precedes final Win32 publication,
since CRT operations can change the native table themselves. Installation is not
atomic across the two interfaces: `InstallationError` preserves its phase, original
error and any separate restoration/publication error. A failed operation does not
claim rollback. `CrtError` retains UCRT errno separately from Win32 error numbers.

Unsafe `detach_console` uses the same installation mechanism for stdin/stdout
and character stderr, retaining one independent process owner per affected slot.
File/pipe/absent stderr stays untouched. Native slot aliases are refused before
mutation. Later failures identify which installation or `FreeConsole` stage
failed; no rollback is implied. Call before handlers and asynchronous users, with
flushed streams and no externally cached handles. The original process identity
is retained. Native control-handler registration must follow detachment because
[FreeConsole resets the handler table](https://learn.microsoft.com/en-us/windows/console/setconsolectrlhandler).

The standalone `windows_stdio` test uses fresh child processes and private files
to exercise both writers, repeated replacement, capability/file Drop, and closed
CRT standard slots while native stdin/stdout remain live. It requires Windows;
cross-compiling the test alone does not qualify its runtime behavior. See the
native [descriptor ownership](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/open-osfhandle)
and [standard-handle lifetime](https://learn.microsoft.com/en-us/windows/console/getstdhandle)
contracts.

## Windows private process pipes

`pipe::Endpoint` generates a local canonical name from 128 bits of OS entropy;
parsing refuses remote, arbitrary and malformed names. Names are bootstrap
locations, not peer credentials. `PrivateSecurityDescriptor` supplies a protected
primary-token-owner DACL with noninheritable security attributes for synchronous
native constructors. The attribute guard borrows its descriptor owner.

Kernel client/server process observations preserve their native errors. A numeric
PID is not original-process authority: `ProcessIdentity` pins an actual process
object and qualifies the connected peer without opening that PID. Its current-
process constructor duplicates the pseudo-handle into a real owned handle.
The lease grants no wait, termination or readiness action. Higher layers own
[async byte channels](../service-runtime/PROCESS.md) and
[bootstrap policy](../service-startup/README.md#windows-parent-bootstrap).
`request_cancellation` returns only the native request/not-found observation.
It never waits or frees active OVERLAPPED/buffer loans; the I/O owner retains
them through completion, as required by
[CancelIoEx](https://learn.microsoft.com/en-us/windows/win32/fileio/cancelioex-func).

## Windows socket activation

`socket_activation` publishes original AF_UNIX/TCP listener records for a suspended
original child. Read-only section ownership, one-shot materialization and failure
retirement follow the [native transfer contract](SOCKET-ACTIVATION.md).

## Verification and constraints

`entropy::fill` uses the OS cryptographic random provider through `getrandom`.
It fills the complete caller-owned buffer or clears it and returns the original
provider cause. It creates no application key or private file and adds no device
path assumption to its consumers.

`cargo xtask verify runtime` runs real sockets and shared framing/CLIENT/Resolver
TCP scenarios on the native host. Native hostname tests do not resolve the host's
own name or change system configuration. FQDN interoperability still requires a
controlled native resolver environment. Platform gaps remain in
[implementation status](../../IMPLEMENTATION_STATUS.md).

## Text input

`stdio::TextInput` owns one original input file. Windows consoles use
[ReadConsoleW](https://learn.microsoft.com/en-us/windows/console/readconsole)
with fixed UTF-16/UTF-8 conversion storage; redirected files/pipes and Unix input
retain raw bytes. No console code page or mode is changed. Blocking execution,
cancellation and worker exit remain the caller's responsibility;
`gnunet-program-host` provides the capacity-one `binary_io::Input::text` owner.

## Special entry removal

`filesystem::Directory::remove_special` removes a selected symlink, socket, pipe
or other special link inside an original caller-owned namespace without following
its target. Ordinary files/directories are refused. The caller excludes concurrent
entry replacement and owns cleanup policy. Unix unlinks relative to the original
directory; Windows opens the original special link with attributes/delete access
and applies native disposition to that handle.
