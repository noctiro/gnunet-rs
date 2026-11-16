# Metadata extraction host

Optional GNU libextractor metadata for the FS adapter. The caller selects the
native library and plugins; the provider runs synchronously on that caller's
worker. See the [FS extraction contract](../fs-std/API.md#metadata-and-automatic-keywords)
for metadata serialization and publication integration.

## Public interfaces

`Selection` preserves the GNUnet `-D` and `FS.EXTRACTORS=-` meanings.
`Configuration::new` validates and owns one absolute library path and exact
plugin selection. Clones share the path and one terminated plugin string.
Configuration parsing and restoration perform no loader operation.

`Authorization::new` is the unsafe native-code trust boundary. Its private
representation cannot be reconstructed from configuration bytes. The caller
certifies the exact library/plugin ABI, lifetimes and environment for future
uses. `for_configuration` only rebinds an existing capability to an equal native
path spelling and exact options; absent and present-empty options differ.

`Provider::open` requires that capability and loads its exact selection on the
existing worker. `extract_file` returns callbacks plus a `SourceStamp` for the
original file. Recheck that stamp around CHK preparation. `extract_bytes` accepts
a separately selected complete borrowed buffer. The [provider controller](src/native.rs)
owns library/list lifetimes; the [callback bridge](src/native/callback.rs) owns
bounded record conversion and panic containment.

The selected dependency must implement the public
[GNU libextractor ABI](https://www.gnu.org/software/libextractor/manual/extractor.html).
Its initialization, plugins, dependencies and loader environment are trusted
native code. Plugin selection uses `IN_PROCESS`; the provider remains on its
owning thread. The framework starts no isolation worker in this profile.

## Example

Selection can be checked before opening a library or worker:

```rust
use gnunet_extractor_host::Selection;

let selected = Selection::from_fs(false, Some(b"-"));
assert_eq!(selected, Selection::Disabled);
```

## Original file inputs

| Platform | Input mechanism | Constraint |
| --- | --- | --- |
| Linux / Android | `/proc/self/fd/N` | The descriptor namespace must be available. |
| macOS / FreeBSD | `/dev/fd/N` | FreeBSD requires the descriptor filesystem. |
| Windows | Original-handle read-only file section | The complete view must fit the admitted virtual-address bound. |

File inputs require an ordinary read-only handle. Identity includes the complete
native file ID; modification and change fences exclude access time. The input
mechanisms preserve the held object across pathname replacement. They provide
change detection rather than an atomic content snapshot. Unix saves and restores
the original cursor even after a caught Rust panic; Windows leaves it untouched.
Neither profile supplies the original extension as a plugin filename hint.

Windows uses a demand-paged read-only mapping without a whole-file Rust heap
copy or a Rust slice over externally mutable bytes. The section prevents
ordinary truncation while mapped. Concurrent writes, native in-page exceptions,
plugin crashes and nonreturning native calls remain provider constraints.

## Configuration and resource bounds

`Limits::source_bytes` bounds admitted file extent. `mapped_input_bytes` bounds
Windows virtual view size; it is not an RSS limit. `memory_input_bytes` bounds
explicit byte-buffer input. Callback count, item count, individual values and
actual retained Rust capacities have separate finite bounds. Native plugin
allocations and execution time are outside those Rust retention bounds.

The same caller guard runs around admission, metadata callbacks and final source
checks. No independent deadline is sampled. Native cleanup runs despite expired
business guards. Failures preserve the caller/native primary cause and any
independent cursor-restoration or mapping/provider cleanup error.

## Observations and cleanup

`Observation::Records` means callbacks were observed. `EmptyUnknown` retains the
public void API's inability to distinguish unsupported input from an internal
plugin failure. Neither observation acknowledges publication.

Explicit `Provider::close` releases the original plugin list before its library
reference. `Cleanup` reports actual calls and loader release success; it does not
claim physical unloading. Drop performs best-effort cleanup. Native loader
errors retain Win32 codes or bounded original POSIX diagnostic bytes.
