# Official host configuration

`gnunet-config` implements GNUnet v0.29.1 host configuration APIs and the
`gnunet-config-diff` command in safe Rust. The ordinary `gnunet-config` binary
is composed in `gnunet-program-host`, which already depends on this crate. Unix account
lookups use `uzers`; real-UID permission checks and descriptor opening use
safe `nix` APIs. This crate forbids unsafe code. It does not recognize private node JSON or migration formats.

```rust
use gnunet_config::{Configuration, Error};
let mut configuration = Configuration::default();
configuration.deserialize(b"[statistics]\nUNIXPATH = /tmp/statistics.sock\n", None)?;
assert_eq!(configuration.get_path("STATISTICS", "UNIXPATH")?,
           std::path::PathBuf::from("/tmp/statistics.sock"));
# Ok::<(), Error>(())
```

`new` / `default` construct an empty convenience configuration, as above. `create(Arc<ProjectData>, Limits)` implements the official project-aware
constructor: it discovers installation paths and creates the eight automatic
PATHS entries. `with_installation` accepts an explicit installation context for
embedding. Project metadata remains associated with duplicates and diffs.

For files, `parse(path)` follows official include directives. `load_from`
loads sorted `.conf` entries in one defaults directory. `load(main)` selects
the project defaults directory, honoring the base-config environment override,
then loads an optional main file and supplies DEFAULTCONFIG if absent. `load_explicit(defaults, main)` is the explicit-directory convenience API. `ProjectData::default_filename` follows the pinned XDG, user and system-file
precedence and distinguishes an unset environment variable from an empty one.

Names and values remain opaque bytes, with ASCII case-insensitive section/key
lookup and the original newest-created-first list order. Values are raw unless
an explicit typed or filename accessor is used. Empty values exist; setting
`None` leaves a removed-value tombstone. Scalar APIs support official decimal,
floating point, size/time, YES/NO, choice and Crockford byte settings. Filename
lists preserve the pinned escaping/tokenization rules.

`get_path` uses the process's read-only environment. `get_filename`,
`expand_dollar`, `expand_filename` and `parse_with_environment` can use a supplied
`Environment` for isolated deployments/tests. Dollar expansion checks PATHS
before environment variables, preserves undefined references, supports braced
defaults, and detects recursive definitions without changing global environment.

`@INLINE@` resolves relative to the canonical source target. `@INLINE-MATCHING@`
uses GNUnet's own limited wildcard matcher and sorted precedence, not shell glob
rules. `@INLINE-SECRET@ section file` imports only that section's final entries,
retains every source definition when diagnostics are enabled, prohibits nested
directives, and records inaccessible secret files without inventing values.

Enable diagnostics before loading to retain ordered `Definition` and `FileSource`
records. Diagnostic serialization includes installation paths, definitions,
include ancestry and native secret-file account/mode details. `clean_file`
conditionally removes redundant physical assignment lines,
preserving effective values, comments, includes, permissions and other bytes. It refuses source changes. `serialize` and `write` use official INI text;
writes publish a fully synced sibling file via rename and follow existing
symlink targets. `duplicate`, `diff`, section removal and dirty-state operations
follow the pinned reference behavior. Selected-section and filename iterators,
abortable filename callbacks, cleanup notifications, parse-and-run callbacks,
and first-use binary-path caches are available as explicit APIs.

`ConfigSettings` and `run_tool` expose configuration-tool operations with
bounded stdout/stderr buffers. The binaries support queries, typed filename
output, section listing, diagnostics, rewriting, diffs, cleaning, RAM input and
the project installation/version profile. The exclusive backend query returns
the official status 77 when no Rust backend is registered; it never treats an
installed C plugin as a Rust backend. The ordinary configuration command selects
the existing ProgramHost logger for `-L` / `-l` and the GNUnet logging environment. Configuration diagnostics use the same borrowed observer route. Explicit process
stderr ownership sends ordinary command errors and section-list headings to the
selected file as well as admitted log records. Configuration, logging and output
failures remain independently available in the command report. Library callers
can prepare a command and execute it with an explicit diagnostic observer; the
unobserved helper refuses logging requests it cannot own. Other unsupported host
requests return an error. `-E` reproduces the pinned C preprocessor-defined
test, including the normal profile's defined macro with value zero. It does
not assert that experimental features are enabled.

`Limits` explicitly bounds input bytes, total bytes, file provenance, include
ancestry, section/key counts, definition history, values, glob inspection and
expansion. A capacity error is not success or a truncated configuration. Like
the C parser, accepted earlier assignments remain applied if a later line fails. Applications needing transactional loading can parse a separate configuration
and publish it only after success.

See [UPSTREAM.md](UPSTREAM.md) for source quirks, reproducible reference commands
and remaining host integration. A normal, unmodified C shared-library caller
executes all 43 configuration public functions and compares 172 trace rows,
files, 24 configuration-command cases and three diff-command cases with
Rust on the tested macOS profile. Permission-denial cases are skipped, without
credit, when run as root. The earlier 44-row extracted component oracle remains
a separate fast check. These results cover this configuration component; the
complete GNUnet utility library remains pending.
