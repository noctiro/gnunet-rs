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
2. Holds the configured parent or its nearest existing ancestor, then creates
   missing child directories relative to that handle and synchronizes their names.
3. Exclusively creates a bounded-name private temporary file in the original
   directory, writes the official stream, synchronizes and closes the writer,
   and keeps a read lease on that same file.
4. Replaces the destination under the held parent, requests that directory's
   barrier and verifies that the destination still identifies the original file.

Unix uses mode 0600 and actual directory `sync_all` calls. Windows uses native
UTF-16 paths and a protected current-user-only file DACL, excluding alternate
data streams. The [native directory barrier](../native-std/API.md#anchored-filesystem-operations)
supports local NTFS when a writable directory lease is available. An unavailable
barrier triggers a flush of the original published file and retains the
`Unavailable` directory result.

An empty persistent set removes an existing ordinary database and requests its
original parent barrier. An absent database creates no file or parents. This
path refuses non-regular entries, including symbolic links. `SaveReport` separates
stored/removed/absent counts from `directory_sync`. Mutations report the combined
barrier result; an unavailable parent barrier cannot be overwritten by a later
synchronized result. An already absent database reports `None`. `Stored`
records file synchronization and name publication. `Synchronized` records the
OS accepting the directory barrier.

The application owns the database path and serializes writers. Configured parent
aliases resolve when the directory is selected. Atomic replacement uses the
original directory entry, including a final symlink if supplied. Callers can
select its target explicitly for stable storage. The application excludes
concurrent in-place writers. A load opens one descriptor, so this adapter's own
atomic replacements expose a complete old or new file. Observed file-length
changes are rejected. Nonregular inputs are rejected before a blocking open;
Windows additionally checks the native AF_UNIX reparse tag, which standard
metadata can classify as an ordinary file.

`StoreError` retains stage, original IO/protocol cause, optional record offset
and `CommitOutcome`. Errors before publication say `DestinationUnchanged`
(temporary files/directories might have been created). Once rename/removal was
attempted, or if the following directory sync fails, the result is conservatively
`Unknown`: the destination may already contain the new snapshot or be removed. It must be inspected/reloaded before a caller decides what to do next. An
ambiguous failed rename retains any surviving candidate. Its reported path is
the configured location at admission. Cleanup before publication targets the
original candidate and reports its independent error. Startup loads only the
configured database entry.

`save_with` gives `CommitBackend` the retained native directory and file for
each namespace operation. Backends preserve errors and return the actual
directory-barrier observation. The store performs file writes and synchronization.

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
