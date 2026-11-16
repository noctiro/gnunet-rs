# Official STATISTICS database storage

The official GNUnet v0.29.1 service uses `[STATISTICS] DATABASE`, resolved with
the configuration filename accessor. Its file is a concatenation of ordinary
STATISTICS_SET messages: a big-endian 4-byte size/type header, flags32, value64,
and two NUL-terminated byte names. A canonical save uses absolute values and
flags 2 (persistent), includes only persistent rows, and has no private header,
UID, watch state, version envelope or migration data.

`Store::new(path, Limits)` takes an already resolved explicit path. It performs
no configuration search or filename expansion. `Limits` bounds complete file
bytes, total replayed/saved records (including duplicate names), and each frame. Stored core row/name capacities remain additional independent bounds. The
record limit counts every replayed SET frame, including duplicate names; it is
not only a limit on distinct resulting rows.

`Store::load::<R,N,C,W,E>()` builds a fresh `Statistics` candidate and returns it
with the bytes/records/rows and `LoadSource`. Missing and empty databases
are explicit successful empty inputs, as at reference service startup. Other
inputs must be complete official SET frames. Load uses normal SET semantics,
including relative arithmetic, unknown flags and replacement of persistence. `Statistics::replay` supplies that no-client operation; the existing `restore`
entry point remains a narrower canonical-dump validator. A corrupt/truncated or
capacity-limited file never publishes a partially restored caller state.

`Store::load_with(factory)` uses that same loader with a caller-created fresh
configured core, including `AllocatedStatistics::with_limits(ResourceLimits)`. The factory runs once before file access; construction failure retains its
original error at `Stage::Preflight`. Rows, clients, watches and queued effects
must all be empty. The loader owns the implementation through the complete normal
read/replay/length validation; failure drops it. The factory does not replace
file loading or turn corrupt input into empty state. Missing/empty inputs retain
the caller's resource limits and their distinct `LoadSource` reports. For a nonempty input, the decoder frame's allocated capacity is charged
in addition to the factory's original external-retained baseline before replay. On success the frame is dropped and that original baseline is restored; errors
drop the unpublished candidate and temporary frame together.

## Saving and publication

`Store::save(&core, scratch)` requires all clients and queued notifications to
be released. This fits service shutdown after its host returns; an IPC
DISCONNECT confirmation is not a filesystem commit. The core is immutably
borrowed while a snapshot is encoded and written. One fallible
`persistent_snapshot()` supplies both passes through `snapshot.iter()`: its
sorted row indices are allocated for the persistent rows, within the
core's remaining retained-memory budget, while names and encoded frames are
not copied into a second full database. Snapshot admission failure retains its
original error at `Stage::Preflight`; it cannot mutate the destination.

On Linux, macOS, FreeBSD and Windows, a nonempty save:

1. Admits all frames, total bytes and work against the explicit limits before
   touching the destination.
2. Creates missing parent directories and requests the backend's directory barrier.
3. Exclusively creates a bounded-name private temporary sibling, writes the
   official stream and calls the file `sync_all`.
4. Replaces the destination with the complete same-directory sibling, then
   requests the parent-directory barrier.

Unix uses mode 0600 and actual directory `sync_all` calls. Windows uses native
UTF-16 paths and a protected current-user-only file DACL, excluding alternate
data streams. File data is synchronized before native same-volume replacement.
Its backend reports `DirectorySync::Unavailable`: it does not issue a directory
barrier or substitute a privileged volume flush. Replacement can fail because
of native sharing or access rules; those failures remain errors.

An empty persistent set removes an existing database and requests its parent
barrier; if already absent it creates no file or parents. `SaveReport` separates
stored/removed/absent counts from `directory_sync`. Mutations report the combined
barrier result; an unavailable parent barrier cannot be overwritten by a later
synchronized result. Already absent reports `None`. `Stored` describes actual
file synchronization and namespace publication, not a power-loss guarantee.
Even `Synchronized` means the OS accepted the calls, not independent proof about
storage hardware or a remote filesystem.

The application owns the database path and serializes writers. Atomic rename
replaces the configured directory entry, including a final symlink if supplied;
callers wanting a symlink target as their stable storage identity must resolve
that identity explicitly. Concurrent arbitrary in-place writers are outside
this ownership contract. A load opens one descriptor, so this adapter's own
atomic replacements expose a complete old or new file. Observed file-length
changes are rejected. Nonregular inputs are rejected before a blocking open;
Windows additionally checks the native AF_UNIX reparse tag, which standard
metadata can classify as an ordinary file.

`StoreError` retains stage, original IO/protocol cause, optional record offset
and `CommitOutcome`. Errors before publication say `DestinationUnchanged`
(temporary files/directories might have been created). Once rename/removal was
attempted, or if the following directory sync fails, the result is conservatively
`Unknown`: the destination may already contain the new snapshot or be removed. It must be inspected/reloaded before a caller decides what to do next. An
ambiguous failed rename retains any surviving candidate path for inspection;
other temporary cleanup is best effort. Orphans after process termination are
never mistaken for the configured database or loaded as a fallback.

`save_with` provides a narrow `CommitBackend` for platform namespace/sync
operations and failure injection. File writing and file synchronization still
use the filesystem. Backends must preserve native namespace errors and return
an explicit directory-barrier observation. Native saving outside Unix and
Windows reports `Unsupported` before mutation.

## Reference differences and tests

The pinned C `inject_message` neglects to validate header.type, and an existing
row in `handle_set(NULL, ...)` reaches `ce->client` without the new-row NULL
guard. Its canonical shutdown dumps contain unique, absolute persistent SETs,
so normal files avoid these issues. Rust rejects foreign message types and
safely replays duplicate names through the defined SET state machine. It does
not reproduce malformed-input acceptance or a NULL-pointer crash.

The tests use files and native synchronization, canonical bytes, restart,
duplicate/relative replay, truncation/corruption/resource rejection, record
offsets, live-client exclusion and a long valid destination basename. Windows
cases also cover native wide filenames, replacement and alternate-stream refusal.
Fault
backends actually replace/remove files before returning an injected error, or
fail directory sync afterward, and assert `Unknown` rather than false success. Two owned child processes are terminated at observed checkpoints immediately
before/after the rename: reload sees only the complete old/new snapshot. That is process-termination coverage, not a power-cut or hardware durability test.

```sh
cargo test -p gnunet-statistics-store -p gnunet-statistics --locked
cargo clippy -p gnunet-statistics-store -p gnunet-statistics --all-targets --locked -- -D warnings
python3 adapters/statistics-store/tests/upstream_oracle.py --source /path/to/pinned/gnunet --output target/new-store-evidence
```

The independent oracle executes original C `save` and `inject_message` bodies
with stdio/configuration shims, compares the generated 60-byte fixture with the
Rust filesystem save, then injects that exact Rust file into the C
handlers and checks all three values. The new evidence directory retains C/Rust
artifacts, commands/exits, input/output hashes and five comparisons. Default oracle mode checks the committed C fixture; `--write` explicitly
regenerates it. These are component tests, not a full C daemon or complete
GNUnet conformance claim.
