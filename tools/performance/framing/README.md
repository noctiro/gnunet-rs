# TRANSPORT TX framing microbenchmark

The runner snapshots source into a new external directory, appends a `cfg(test)`
probe after the exact production framer prefix, builds the package in
release mode, and runs seven bounded workloads through owned Unix socket pairs.
It never edits the measured workspace. Output directories cannot be overwritten.

```sh
python3 -B tools/performance/framing/run.py --workspace /path/to/source \
  --admission borrowed --output /tmp/frame-before-NEW
python3 -B tools/performance/framing/run.py --workspace /path/to/refactored-source \
  --admission owned --output /tmp/frame-after-NEW
```

The only probe adapter difference is the old `queue(&bytes)` versus the new
`queue_owned(bytes)` call. Each generated frame has a common GNUnet header and
per-frame/per-round sequence fields. The peer checks every byte and ordering
after the timed interval. This is not an application protocol or C peer test.

The seven `(frame bytes, batch frames)` workloads are `(64,1)`, `(64,4)`,
`(64,32)`, `(64,256)`, `(1024,32)`, `(16384,4)`, and `(65535,1)`. Each fresh
process warms up 40 batches and times 400. The default runs three processes per
case. Latency covers allocating/enqueuing the engine-like owned frames, actual
TX, and raw peer `read_exact`; validation is outside timing. RX framing,
cryptography, domain state, C interoperability and node behavior are excluded.

Positive write-poll count is an native-positive-write count only while
the measured wrapper's `Ready(Ok(()))` has that exact contract. Review that
contract before comparing a new implementation; synthetic completion receipts
must never be counted as extra native writes. It does not count failed attempts.

RSS comes from the process's `ps` observation and may be null. CPU and allocator
events are not instrumented. Co-running jobs, OS scheduling, socket buffers and
allocator caching affect these measurements; the machine is not isolated. Store
the exact source, build, executable, probe and metrics hashes, compare repeated
runs and write counts, and do not extrapolate this microbenchmark into a product
or Rust-versus-C speedup claim. Complete release performance work still requires
comparable node workloads and latency, throughput, CPU, memory and allocation
measurements under equivalent protocol and security behavior.

Schema2 receipts record the runner hash, Cargo/Rust compiler versions,
build and workload arguments, and executable hashes checked before and after
each process. Earlier schema1 receipts retain their original narrower provenance;
updating the runner does not change the evidence attached to those runs.
