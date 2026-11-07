# Normal private DV interoperability

`dv_private.py` drives three normal nodes A–B–C over private Unix communicators.
The middle TRANSPORT can be unchanged official C or Rust. Each node runs normal
STATISTICS, PEERSTORE, PILS, NAT, TRANSPORT and CORE; NAT precedes TRANSPORT. Only
the exact A↔B and B↔C HELLO edges are imported. No topology, gossip or DHT process
adds a hidden direct A–C path.

`dv_core_client.c` links the unchanged official CORE/application public APIs. Two
callers suggest only B and each submit one fixed16-byte application payload in
the official TEST message (type0). Passing requires each exact opposite payload
from the correct remote peer, the separate `PEER_MQ_HANDOFF` event, successful
original caller exit, official CLI established two-hop Unix route lists,
and clean shutdown of every original normal service. The caller is a public API
component, not a C CORE daemon or a substitute peer implementation.
The handoff reports only the official peer MQ's local CORE-client queue event.
It does not prove an IPC write, downstream acceptance or a remote acknowledgement;
the two payload receives remain the data-delivery evidence. The original
caller completion and exit policy is unchanged.

The manifest binds the current source map, normal Rust Cargo cohort,
unchanged native C build/index, component compiler/header/library inputs, every
selected C library/default and the complete expanded default configuration.
`config_dump.c` uses the public configuration APIs for that expansion. Ordinary
YES/NO values stay strings; unresolved variables prevent runtime admission.
The expansion retains its own config-dump producer, source bindings,
binary hash, underlying C build, original output and bootstrap. That producer
may differ from the current CORE caller's component build: changing the caller
does not require rerunning an unchanged configuration exporter. The config-dump
binary is a preparation input, not a required runtime participant. Old bound
producer inputs stay immutable; rebuilt callers use separate source/output paths.
Every mutable endpoint, store, key and monotonic-time file belongs to its private
node. HOME/home/CODEX_HOME retain their values.

Run only within the authorized private scope:

```
python3 tools/reference/dv_private.py --manifest /ABS/manifest.json --output /ABS/new-evidence --middle c --execute
```

The existing Controller owns each original process, native target, bounded
capture and consuming wait. The case has at most3 nodes/64 original children,
2MiB per stream and96MiB total output, a240s global target with cleanup reserve,
and original130s absolute/140s native data-caller targets. Optional early route
lists never extend them or substitute for data/route success. Public networking,
audio/devices, privileged actions, dependency downloads and benchmarks are not
part of this runtime driver. Failures retain their output and cleanup
outcomes; missing earlier temporary evidence is never reconstructed as a pass.

The explicit manifest diagnostic mode `reference-single-neighbour-validation`
imports only A↔B. C remains isolated while the unchanged C TRANSPORT logs its
existing validation/queue/flow events through a fixed function/line filter.
Observation ends after75 seconds; original caller targets are not renewed.
Its `observed` outcome means only that the bounded capture completed and all
original children/captures/resources retired cleanly. It supplies no normal
three-node interoperability credit and retains its private evidence directory.

The shared staging helper copies all defaults declared by the Meson map.
Each build profile supplies its own required filenames. Resuming a failed later
stage reuses only regular destination files matching the exact original size and
SHA-256, and records reuse; differing or symlink destinations are refused. It
does not rerun an already successful compiler or overwrite a different output.
