# Native process contracts

## POSIX locale and regular expressions

This implementation profile is an ordinary initialized Darwin process libc, or
GNU libc on a Linux `target_env="gnu"` target. Apple's loader-only VARIANT_DYLD,
other libc implementations and other native ABI profiles are not covered by the
source argument below. A public libc source snapshot identifies the source profile; it does not identify
the installed OS binary.

`native-contracts/sources.json` retains exact primary repository revision, Git
blob SHA1, byte size and SHA256. Retention checks recompute the full Git blob
header/hash, so files are exact copies rather than hand-written recipes. These
sources are evidence only and are never compiled into production.

* Apple Libc1752.100.10 revision71bbe350ab79eef58113991d817ccc6165061a64,
  locale/xlocale.c461..480: uselocale rejects invalid locale magic; otherwise it
  retains the chosen object, uses its initialized locale TSD key, and releases
  the previous TSD reference. Its initialization uses a fixed library key. The
  private owned selector and the saved prior selector must remain valid during
  every short operation. [Pinned Apple source](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/locale/xlocale.c).
* Apple libpthread539 revision42d026df5b07825070f60134b980a1ec2552dfee,
  src/pthread_tsd.c205..236: ordinary pthread_setspecific uses an existing
  thread's TSD array. A valid static key writes an existing array slot with no
  allocation; the loader-only branch is distinct. It is not modeled as a normal
  recoverable resource allocation failure for this declared libc profile.
  [Pinned pthread source](https://github.com/apple-oss-distributions/libpthread/blob/42d026df5b07825070f60134b980a1ec2552dfee/src/pthread_tsd.c).
* glibc revision04e750e75b73957cf1c791535a3f4319534a52fc,
  locale/uselocale.c29..70 changes locale/category TLS fields directly. No
  per-selection heap allocation or ordinary error return exists in that body.
  [Pinned glibc source](https://github.com/bminor/glibc/blob/04e750e75b73957cf1c791535a3f4319534a52fc/locale/uselocale.c).

GNU's documented regex interface requires the compile and execute locales to
agree. [GNU libc regex contract](https://sourceware.org/glibc/manual/latest/html_node/Matching-POSIX-Regexps.html).
Each Rust Regex owns an independent duplocale snapshot, compiles exactly
once, and selects that same owned snapshot for regcomp, regexec and regfree.
Every short guard restores the prior calling-thread selector before a caller or
custom logging callback resumes. A retained parsed-once rule is not recompiled
when another locale is selected. The Rust-only locale-switch witness exercises
only this repaired wrapper; it never runs the old undefined C cross-locale
regexec sequence and claims no normal-C equality for that sequence.

Snapshot/entry failures and REG_ESPACE/other native failures propagate as
ordinary errors. REG_NOMATCH alone means a negative match. Errors never fill a
callsite cache. Invalid pattern syntax retains the original C prefix-of-rules
behavior. Logger/Policy enabled and setup interfaces are explicitly fallible so
native resource failures cannot be disguised as successful filtering/setup.

A valid privately owned live selector cannot become invalid through safe calls.
Under the profiles above, final Drop cannot encounter a normal selector resource
error. If ownership or the trusted ABI invariant is nevertheless broken, Drop
fails stop before freeing under the wrong locale or freeing an installed
object. That final abort is not a normal resource strategy, is not tested by
passing invalid locale pointers, and is not evidence for an unvalidated libc.
No unbounded abandonment/quarantine queue is created.

The separate CONFIG native locale capsule provides an explicitly unsafe acquired
current-thread reader/effect capability. Caller obligations include excluding
concurrent native global mutations and keeping externally installed selections
valid through synchronous operations, until every retained configuration/context
clone is dropped. Immutable locale snapshots remain separate: they do not track
later arbitrary setlocale/uselocale calls.

The source numeric-C float locale uses the *actual* newlocale mask/NULL-base
semantics. In this pinned Apple implementation, NULL base duplicates the calling
thread's current locale, which may be global or a prior retained thread locale;
it does not universally make the other categories C. A failed CONFIG float scan
leaves that mixed locale selected, and a later global reset may therefore leave
this thread's prior character rules intact. Successful calls restore the prior
selection. The Rust capsule owns the retained failed-scan object in TLS and
detaches it before final release. A late TLS-destructor attempt returns a boundary
error instead of pretending that a failed ownership installation succeeded.

Out-of-range scanf inputs are never executed: a defined strtof_l range preflight
rejects them, with no scanf/source equivalence claim. All tested ordinary lexical
failures are defined and use correctly typed initialized outputs. The independent
normal-C actor calls the unchanged GNUnet public API with the required argument
ownership. Fixture failures cannot establish interoperability.

## Configuration locale binding

`CaseContext` is explicit caller-owned mutable selection. Immutable snapshots do
not automatically track external setlocale/uselocale calls; the separately acquired
CurrentThread capability reads that calling thread at each synchronous source read
point under its documented foreign-mutator/lifetime contract. Configurations/duplicates/secret
children sharing that context observe later selection replacements without
rewriting names, values or order. Retained `CaseSnapshot` views keep independent
native ownership alive after replacement/context Drop. PROGRAM's native installer
owns/publishes one such context. Embedders can bind an existing context before
config creation/duplication to model one C caller's effective locale.

Section/key lookup, directive names, PATHS exclusions and choices use the
selected byte comparison context. Whitespace uses unsigned-byte classification;
empty spans and embedded NULs are handled before bounded native string calls.
Numeric accessors retain their explicit range checks and numeric-locale rules.

## Windows regular expressions

Windows uses a safe Rust BRE parser and boolean instruction machine, including
groups, references 1..9, intervals, brackets and POSIX character classes. Unescaped
`+?()|{}` are literals. Extensions include escaped alternation/plus/question,
word boundaries, `\w` and `\s`. Empty branches/groups are accepted. Input uses
the lossless local string codec; supplementary scalars remain whole and isolated
UTF-16 units remain exact literals. C-string prefixes end at NUL.

The native adapter retains CRT character properties and selects system ICU
collation from the captured NLS locale identity. C collation stays ordinal.
Named cultures use one owned ICU profile for full/primary ordering and actual
contraction membership; arbitrary Unicode sequences are not collating elements.
Ranges and equivalence classes use the inventory's maximum scalar width, even
when their named endpoints are single characters. Negative brackets preserve
excluded-element checks and consume the complete permitted collating element.
Native failures never become negative matches.

Named collation requires Windows inbox ICU: the combined `icu.dll` on 1903+
or the split layout and a scoped COM reference on earlier supported systems. Language/script and alternate-sort identities are checked after native
resolution; unsupported mappings fail explicitly. ICU/CLDR data is a declared
provider choice and need not match NLS or a different libc's locale tables.

No captures escape this API, so matching explores valid capture histories without
selecting returned leftmost-longest captures. For example, `^\(a*\)a*\1$` matches
`a`; the observed Darwin native profile rejects that fixture. The portable native comparison
tests cover the shared nonempty grammar and do not prove identical behavior for
every libc capture or locale profile.

Bounds are 16384 pattern symbols, 65536 input symbols/instructions/retained or
pending states, 64 nested groups and 4000000 work units per compilation/search. Variable-width spans and native
comparison extents consume that work budget. A first-scalar inventory index
limits candidate scans to relevant contraction widths.
Named collating sequences are limited to 64 symbols. Allocation, native and budget
failures propagate through the existing fallible policy API. Invalid syntax
retains the source's preceding-rule-prefix behavior. Windows native runtime
qualification remains in [implementation status](../../IMPLEMENTATION_STATUS.md).

## Absolute calendar input

POSIX retains the source's ordered strptime formats, partial-field reuse and
mktime normalization. Windows uses the native adapter's retained LC_TIME parser,
wide ISO/ctime/OLE input and named NLS pictures for supplemental cultures.
Checked Gregorian arithmetic supports expanded ISO years across the complete
GNUnet microsecond domain. Local conversion keeps the UCRT fast path and uses
Windows year-specific rules or explicit Microsoft TZ outside its range. Windows
ISO month/year inputs use the first day instead of normalizing an initially zero
day. Native calendar providers retain their own era/range constraints.
Both program backends preserve the C-string prefix before NUL, return saturating
microseconds and report invalid options through the existing public error API.
Neither backend changes locale or TZ while parsing. Windows runtime qualification remains
open in [implementation status](../../IMPLEMENTATION_STATUS.md).

## Process stderr

`ProcessStderr` is an explicitly unsafe acquired, non-Send/non-Sync capability.
It coordinates only callers of this API. The process must exclude foreign
standard-stream users, mutation and spawning during installation, and flush
buffered writers beforehand. Dropping the claim leaves the installed stream live.

Unix lifts private descriptors above 2 before `dup2`; no caller-owned file can
later close installed fd2. Windows delegates to the native adapter's separate
Win32/UCRT owners, restores temporary standard-table changes and returns typed
partial-installation failures through the original `io::Error` chain. See the
[native ownership contract](../native-std/API.md#process-standard-streams).

## Windows localization

Enabled NLS requires a trusted GNU libintl DLL at a fully qualified path. The
native loader owns its reference and preserves load/export errors. The selected
ABI includes `libintl_setlocale`, GNU LC_MESSAGES1729 and
`libintl_wbindtextdomain`: catalog directories are bound as absolute UTF-16 paths
without a narrow-codepage conversion. The UCRT-only ABI has no gettext message
category and is refused before loading. An unavailable export or failed binding
is an enabled-NLS error. The explicit disabled-NLS profile remains separate.

Translation/context clones retain their documented library and locale authority.
The native loader test exercises Windows system exports; it does not establish
GNU gettext catalog selection. Qualification remains in the
[central status](../../IMPLEMENTATION_STATUS.md#pending-qualification).
See [GNU directory binding](https://www.gnu.org/software/gettext/manual/gettext.html).
