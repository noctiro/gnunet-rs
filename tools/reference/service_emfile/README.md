# Native service EMFILE suspension observations

The pair uses an unchanged normal C `gnunet-service-statistics` daemon and a
Rust component fixture built from the public `serve_statistics_on` API. The
fixture declares 1100 client slots, which exceeds the official native 1024 FD
boundary. It is not the production Rust app or its default capacity, and this
receipt does not complete a generic SERVICE/STATISTICS owner.

For each process, first fill one listener with clients whose official
GET has returned END. The next accepted socket crosses the native FD_SETSIZE
boundary and is closed before admission. Its peer observes EOF/reset. A
read-only `lsof` snapshot records all 1024 numeric descriptors and maximum1023;
the test parent retains its original high RLIMIT, which is not changed. Then:

1. Queue exactly one GET on the opposite listener. It cannot consume the one
   descriptor that will later be released before the intended observation.
2. Observe no response for350ms, while an original admitted client still GETs.
3. Close the already rejected/unadmitted trigger peer. The queued request still
   has no response for650ms more. No timer-based or unadmitted-close retry is
   treated as success.
4. Physically close exactly one original admitted client. The opposite listener
   must return the official END, and another original client must
   still work.
5. Close every remaining owned peer. Gracefully stop/reap the original process
   and verify all private runtime directories were removed.

The Unix-fill/TCP-queue and TCP-fill/Unix-queue profiles run separately. This
avoids two waiting connections competing for one freed descriptor and creating
an unrelated second EMFILE. Different runtimes may reserve different baseline
FDs, so equal admitted-client counts are not required. Actual counts and all
raw events are retained. Both runtimes happened to admit1016 clients in the
current Darwin observations. Rust also reports exactly one native EMFILE per
profile and a final report with one rejected stream and all admitted
clients closed; the core client count must be zero.

Source anchors in the fixed v0.29.1 tree are `service.c:do_suspend`,
`accept_client`, `do_resume`, `finish_client_drop` and
`network.c:initialize_network_handle`. The C service suspends all listen tasks
on EMFILE and resumes on the close of a non-persisted admitted client,
unless shutdown is also active. STATISTICS never calls client_persist, so the
persisted generic-SERVICE branch is source-reviewed here but is not exercised
by these daemon processes. A finite one-second no-response window is an
observation, not a claim that time alone proves infinite suspension.

All configs, HOME, BASE and XDG paths are new private directories. Connections
use only owned Unix sockets and127.0.0.1. The C daemon has no DATABASE. No public
DNS, user config, system accounts, services, `/etc` writes, process-limit
changes or mutable C libraries are used.

The fixture is in `adapters/ipc-unix/examples/service_emfile.rs`; the paired
verifier is in this directory. Historical isolated handoffs and C-only trials
certify their recorded inputs and do not replace a current-source run.

```sh
python3 -B verify.py --repo /absolute/repo \
  --receipt /absolute/normal-statistics/build-result.json \
  --reference-helper /absolute/repo/tools/reference/build_reference.py \
  --output /absolute/new-output
```

The output must be disjoint from every input. The wrapper uses pinned
Cargo1.99.1, offline/locked builds, jobs2 and an output-local target; it validates
one Cargo compiler artifact rather than guessing a previously compiled
binary. It runs strict package lints and the four process profiles. Sources,
file membership, tools, receipts, binaries, C source and normal libraries are
bound and checked before/after. The current native observation profile requires
`lsof` at `/usr/sbin/lsof` and a parent RLIMIT_NOFILE above8192; other platform
profiles fail visibly rather than substituting a source component or mock.
