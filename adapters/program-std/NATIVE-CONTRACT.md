# Native locale / regex boundary

This implementation profile is an ordinary initialized Darwin process libc, or
GNU libc on a Linux `target_env="gnu"` target. Apple's loader-only VARIANT_DYLD,
other libc implementations and other native ABI profiles are not covered by the
source argument below. The current runtime evidence is Darwin arm64 macOS27.0.1
build26A434. A public libc source snapshot is not claimed to be the installed OS
binary; native process/profile observations and source inspection are separate.

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
normal-C actor calls the unchanged GNUnet public API. A previous owned observer
mistakenly passed stack input to the ownership-transferring dollar helper; that
SIGABRT is retained as a failed fixture, receives no credit, and is not repeated.
The corrected actor transfers GNUNET_strdup ownership, records all compiler bytes
and treats its own const/prototype/lifetime diagnostics as fatal before execution.
