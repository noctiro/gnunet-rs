# Reference contract and evidence

The baseline is GNUnet v0.29.1, commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.

- `src/lib/util/configuration.c`: parser, precedence, includes/secrets, accessors,
  source definitions, serialization, duplicate/diff, cleanup and atomic writes.
- `src/lib/util/strings.c`: filename, fancy size/time and Crockford conventions.
- `src/lib/util/disk.c`: the actual `GNUNET_DISK_glob` and `glob_match` rules.
- `src/lib/util/os_installation.c` and `src/include/gnunet_os_lib.h`: project
  data, installation path construction and binary-path caches.
- `src/cli/util/gnunet-config.c` and `src/cli/util/gnunet-config-diff.c`: command behavior.

The production implementation is independent Rust and never links GNUnet C.
There are two distinct reference checks. The fast component oracle extracts original
C function bodies into a temporary program, retaining the original license
notices. Shims provide allocation/logging and reject include dispatch. It does
not substitute handwritten C parser or conversion logic. File includes and the wildcard helper are covered by Rust filesystem
and boundary tests separately. This 44-row differential does not execute
GNUNET_DISK_glob or file include loading and makes no complete-daemon claim.

```sh
python3 adapters/config-std/tests/upstream_oracle.py --source /path/to/pinned/gnunet
python3 adapters/config-std/tests/upstream_oracle.py --source /path/to/pinned/gnunet --output /new/evidence/directory
cargo test -p gnunet-config --locked
cargo clippy -p gnunet-config --all-targets --locked -- -D warnings
```

Default oracle mode compiles and executes C, verifies 44 rows against
retained fixtures, and reports source hashes. `--output` additionally compiles
and executes the unique Rust function-trace test, retains a copy of its
binary and its trace, compares every C/Rust row, and records commands,
nonzero executed counts, binary/log/source hashes and input invariance. Empty or
filtered-out Rust tests cannot produce a successful receipt. `--write` is a
separate explicit fixture-regeneration operation.

The normal reference check compiles `normal_api.c`, an ordinary caller of all
43 configuration public functions, against an unmodified normal C
`libgnunetutil`. It compares 172 C/Rust trace rows and written files, including
defaults, includes, limited globbing, secrets, diagnostics and cleanup.
Optional normal C command binaries additionally exercise 24 configuration
cases and three diff cases. The commands compare stdout, exit status and
written files; stderr is retained, without claiming byte-identical generic
logging. Unix unreadable/default-directory traversal and denied-write cases
are permission failures for an ordinary user. Root runs explicitly skip
them and receive no denied-access credit.

`build_normal_reference.py` creates a new normal Meson build and prefix using
the maintained reference builder, then builds and copies the two unchanged C
configuration programs. It leaves earlier reference binaries intact. Pass
the same private dependency prefix, Meson/Ninja paths and compiler environment
used for the normal reference build:

```sh
python3 adapters/config-std/tests/build_normal_reference.py \
  --source /path/to/pinned/gnunet --output /new/build --prefix /new/prefix \
  --deps-prefix /path/to/private/deps --meson /path/to/meson --ninja /path/to/ninja
cargo build -p gnunet-config --bin gnunet-config-diff --example configuration_trace --locked
cargo build -p gnunet-program-host --bin gnunet-config --locked
python3 adapters/config-std/tests/normal_reference.py \
  --reference /new/build/build-result.json \
  --configuration-reference /new/build/configuration-result.json \
  --rust target/debug/examples/configuration_trace \
  --rust-cli target/debug/gnunet-config --rust-diff target/debug/gnunet-config-diff \
  --output /new/evidence
```

The receipt records source/compiler/build inputs, program hashes, raw
logs, normalization of the owned fixture root, source and participant
invariance, and temporary-directory cleanup. Direct calls to every function
are API-surface coverage, not proof of every platform or input combination.

The helper-path API also accepts an independently selected `ProjectData` through
`suid_binary_path_for_project` and `suid_binary_path_for_project_with`. The
configuration supplies only `PATHS/SUID_BINARY_PATH`; the explicitly passed
project controls native fallback discovery. Existing `suid_binary_path` methods
remain conveniences using the configuration's own installation context. Both
global and caller-owned caches retain the first successful SUID prefix/libexec
directory, so reusing one cache with another project keeps the original fallback.
Absolute paths bypass discovery and do not populate these caches.

The separate normal-library check starts a fresh C/Rust process per scenario and
compares distinct configuration/project contexts, reversed first-project order,
raw SUID prefix caching, empty-prefix fallback, absolute bypass and the original
convenience methods. It only constructs strings using owned temporary empty
directories and ordinary non-executable files; no resolved program is executed.

```sh
cargo build -p gnunet-config --example suid_project_trace --locked --offline
python3 adapters/config-std/tests/suid_project_reference.py \
  --reference /path/to/normal-statistics-build/build-result.json \
  --rust target/debug/examples/suid_project_trace --output /new/path-evidence
```

## Pinned details reproduced

- Tabs and CR bytes become spaces before parsing. Full-line `#` and `%` comments
  are recognized; inline comments, semicolon comments and backslash unescaping
  are not invented. Surrounding double quotes are removed only as the C parser
  removes them. Empty section headers alone do not create stored sections.
- Case-insensitive replacement retains original spelling and list position.
  New sections/keys are inserted at the front. A failed later line leaves prior
  accepted values in place. File parsing restores the prior dirty indication.
- The reference setter itself does not mark dirty. Removing a section with
  entries does; writes clear it on success and mark a write error on failure.
- Serialization omits installation PATHS, writes literal LF as `\\n`, and does
  not add quoting. The parser does not turn `\\n` back into LF. Consequently the
  reference API does not promise that arbitrary programmatically set whitespace
  or LF values round-trip through the text format.
- Fancy conversion allows joined units, repeated units, bare units and sums;
  unsigned products/sums wrap. The decimal TB/PB/EB table contains a historical
  1024 factor, retained here. Only YES/NO are official booleans. Negative decimal
  magnitudes within u64 are converted to the unsigned two's-complement value.
- Dollar names outside braces stop only at slash, backslash or space. PATHS
  takes precedence over environment; an existing empty value suppresses a
  default. Unknown variables and unmatched closing braces remain literal.
- Filename `~user/file` is HOME plus `user/file`; it is not passwd lookup.
- Matching includes use GNUnet's limited wildcard code: only `*` is special and
  only in the final component, `?` is literal, hidden names are included, and
  `+`, `[` and `~` anywhere in the pattern are rejected. The original matcher
  returns false when a trailing star would consume a nonempty suffix; that
  behavior is retained, rather than silently replacing it with POSIX globbing.
- Inaccessible secret sections can retain previously defined visible entries.
  Their missing contents do not fabricate empty-string values. Restricted
  sources reject every directive, including ones under unrelated sections.
- Installation paths preserve trailing slashes and the reference LIBEXECDIR
  double slash in the tested non-multiarch layout. Diagnostic installation
  labels preserve the source switch's fallthrough behavior. Explicit empty
  prefix and XDG variables suppress their unset-variable fallback.
- The normal configuration command's version option prints its version and
  continues normal argument processing; version alone consequently exits 2.
  `-E` uses `#ifdef GNUNET_EXPERIMENTAL`: the normal generated profile defines
  the macro to zero and therefore returns success. `BuildProfile` exposes
  definedness and value separately; this is version-profile metadata only.
- Conditional cleanup compares exact original bytes before publication and
  again immediately before rename, corresponding to the C hash comparisons.
  Neither implementation provides an atomic compare-and-swap against a writer
  racing after the last check.

## Safety boundaries

The C parser indexes original physical length after advancing leading whitespace;
multiple leading bytes before a section can cause out-of-bounds reads. Embedded
NUL bytes can likewise make its allocated/string lengths disagree. Safe Rust
rejects embedded NUL and recognizes section headers only at the well-defined
unindented, unpadded boundary; ordinary malformed sections return syntax errors.
Unsigned scanf overflow has undefined C semantics, so overflowing numeric
magnitudes are explicit Rust errors. The C dollar helper's depth guard does not
bound all recursive re-entry; Rust bounds nested defaults and detects reference
cycles instead of risking stack overflow.

This bounded host profile accepts regular configuration files and follows their
symlinks. Unix opens are nonblocking and validate the opened descriptor as a
regular file, so replacement by a FIFO or device cannot silently become an
ordinary input stream. This does not make pathname identity or the preceding
real-UID/ACL readability check atomic. Non-regular secret sources are marked
inaccessible, matching the reference secret-file readability test. Explicit
serialization and query APIs can return secret values; they do not promise
secret-buffer zeroization.

C serialization's sizing pass skips an inaccessible empty section while its
writing pass does not, allowing an allocation overrun. Rust consistently skips
that section. These undefined-memory cases are not copied into safe Rust.

## Native platform mapping

The pinned C observations above describe their Unix host profile. Windows keeps
the same configuration grammar, values and cache ownership with native drive,
UNC and UTF-16 filesystem paths. Matching includes validate wildcard syntax in
the final component; literal parent directories may contain `+`, `[` or `~`
(including short Windows profile names). Unix retains the source's whole-pattern
check. Windows file publication uses protected initial permissions and preserves
an existing destination's ACL; failed publication retains recovery information
as described in the [configuration API](README.md#diagnostics-and-publication).
Native Windows tests establish those host mappings independently; the Unix C
comparison does not certify Windows filesystem or permission behavior.

Windows numeric-C conversion uses owned UCRT locale objects and defined native
conversion with trailing-whitespace validation. It leaves thread/global locale
unchanged on success and failure. The POSIX current-thread capability retains
the pinned source's failure effect under its explicit native ownership contract;
that implementation detail is not imposed on the Windows backend.

## Reference limitations

Project metadata, environment/default selection, PATHS construction, native
account diagnostics and configuration-tool operations are implemented and
covered by the normal reference profile. The following remain explicit gaps:

- Automatic Darwin discovery does not enumerate dyld shared-library images in
  the C library's priority order. Embedders can provide exact locations;
  current-executable/PATH discovery is available. Linux proc-map/PATH discovery
  is implemented but is not certified by this macOS run; other OS installation
  layouts and positive `/etc` fallback selection need their own native runs.
- `--supported-backend` is exclusive and returns the official unavailable status
  77 because this frontend selects no Rust backend registry; an installed C plugin
  does not establish Rust backend availability. The ordinary `gnunet-config` binary
  in `gnunet-program-host` selects the existing generic logger, including `-L`,
  `-l` and environment policy. Configuration events and ordinary stderr use that
  selected destination. Concise help retains this frontend's existing bytes; it
  does not reproduce the generic gettext/getopt help formatter byte for byte.
- `--cflags` and `--libs` require installed C development headers and
  library files. The normal oracle stages reference files for these
  checks. A Rust-only installation does not claim a C ABI development package.
- No complete utility-library, crash-durability, or atomic concurrent-writer
  guarantee follows from these configuration checks. The complete `util`
  ledger entry remains pending.
