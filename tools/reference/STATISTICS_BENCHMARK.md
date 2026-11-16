# STATISTICS component benchmark

`statistics_benchmark.py` compares normal C and Rust STATISTICS services through
the same unmodified C CLI. It uses private Unix endpoints, memory-only services,
absolute nonpersistent SETs and a fresh GET requiring the current value.

```sh
python3 tools/reference/statistics_benchmark.py --manifest /path/to/manifest.json --approval /path/to/approval.json --output /private/tmp/fresh-benchmark-evidence
```

## Workload and bounds

The manifest fixes warmup/sample counts. Defaults are two warmups and twenty
SET/GET pairs per backend, alternating backend order. Limits are four warmups,
twenty-five samples and 128 owned participants. Each SET is issued once; a wrong
or missing GET result fails rather than replaying it.

Defaults are 300 seconds total, ten seconds per startup/command and a separate
ten-second cleanup bound. Startup shares one deadline through launch, READY and
socket appearance. Protocol results, not a pathname, determine readiness.

## Metrics

Latency includes normal CLI startup, IPC, exit, capture and validation. Reports
contain nearest-rank p50/p95, min/max and serial CLI-lifecycle rates; these are
not service-only latency or saturation throughput.

The optional resource sampler observes the still-owned process without reaping.
CPU differences require compatible platform/source/start markers and ordered
counters. Missing/unsupported values stay null. Sampled maximum RSS is distinct
from an OS lifetime high-water mark and from benchmark-phase peak memory.

## Inputs and results

The manifest binds build receipts, source maps and artifact hashes. The separate
expiring approval input binds the selected manifest, controller, process owner
and optional sampler. Outputs must be fresh; ambient configuration, activation,
autostart and database state are excluded.

`conversation_owned.py` retains process/pipe/deadline ownership. The caller must
leave children waitable, use default SIGCHLD and avoid concurrent reaping. Results
retain samples, captures, failures, cleanup and before/after input checks.
Uncertain retirement, capture failure, input changes or failed cleanup prevent
completed status. Blocking OS calls cannot promise forced preemption.
