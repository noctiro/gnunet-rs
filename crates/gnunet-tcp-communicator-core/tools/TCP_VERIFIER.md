# Maintained integrated TCP verifier

Run `verify_session.py` with explicit absolute `--repository`, `--source`,
`--reference`, `--component-reference` and a new `--output` directory. Outputs may
be external or under the original workspace's explicitly excluded `target/`;
source paths/ancestors and overlapping reference/tool directories are rejected.
The peer reference kind is `unmodified-official-c-tcp-peer-services-reference-build`;
the component kind is `unmodified-official-c-tcp-communicator-reference-build`.
Both must bind unchanged v0.29.1/346358e26d4dcc2dc4f51bef5d52dca29c7d8165.
`PYTHONOPTIMIZE=1` is supported: critical checks raise explicitly and a real
optimized Python child is tested with a nonzero process result and a positive control.

The verifier copies the complete workspace into `OUTPUT/workspace`, including
all members, `.cargo` settings, toolchain/format settings and both root and embedded
Cargo locks. It generates no subset manifest or production source. Complete
default/all-features/no-default-features metadata, every normal/dev/build/target/
rename/optional/default/feature declaration, resolved graph, all architecture roles
and both registry/checksum contracts must match the original checkout. There is
exactly one local session-crypto package identity. Workspace xtask architecture,
feature, lint and noalloc checks run in the copy, using a Cargo-JSON-selected binary.
The workspace includes dev-only tokio-macros2.7.2; this is explicitly recorded rather
than described as zero registry change. The noalloc lock must exclude it.

Only the integrated TCP core, TCP host and shared session-crypto packages are
selected for the named79 runtime/9 compile-fail suite, strict all-target Clippy and
rustdoc. Eleven test executables are obtained from `cargo test --no-run` JSON,
hashed before execution and compared with the run. Example executables
are always selected from Cargo JSON, never guessed under target/debug. Both full
embedded noalloc fixture builds use their copied manifest and lock.

The current C component checks retain thirteen cipher/HMAC/signature fields under
O0/O2, all1151 Rust/2302 C finite Elligator observations, and five service/layout
fields. Actual compiler dependency files bind full header/source sets before
compilation, from the compile and again after execution, including SDK and
external headers. References validate complete tracked C source state, original
Meson source/build/prefix arguments, historical builder/input hashes, declared
libraries/private configuration/compile database and fresh dynamic providers.
Fresh provider/header hashes supplement historical receipts; no old undeclared
hash is invented. System shared-cache code remains an explicit native platform profile.

The normal-peer profile starts fourteen owned original processes on numeric
loopback/Unix endpoints, using unchanged normal C services and communicator.
Fresh C caller and Rust example hashes are bound from compilation to process start
and exit. It requires forty sends and forty receives on both raw TRANSPORT sides,
three preseed callbacks and three nonzero timestamp replacements in the
normal SQLite database, normal rekeys, all process exits0 and a Closed,
quiescent Rust owner. The local sandbox blocks public IP traffic. No daemon/system
service is installed, public DNS invoked, C source/binary altered or known C UB
path deliberately exercised.

Seventeen named controls preserve the original four and cover full-role members,
all dependency fields, graph features/kinds, both locks/settings, file additions/
deletions/modes/symlinks, registry identities/checksums, duplicate session identity,
reference source/setup/builder/artifacts and optimized-Python rejection.
The complete tools directory, recursively, must contain no active Python
assert statements. Both active normal builders use explicit raises, tested
as real `python -O` subprocesses before Meson admission and with a valid admission
control. `historical-builders.json` separately binds the exact original builder
bytes used by immutable existing C receipts. Those bytes are inert, non-executable
`.snapshot` data under `history/`; they are never imported or run. Reference
receipts explicitly report historical provenance when used, and verify original
archive SHA, replacement builder SHA, profile kind and the provenance map. No old
receipt hash or old C binary is rewritten to pretend it used the replacement code.

`--prepare-only` writes only `preparation.json` for copy/contract development;
it writes no acceptance result. `--development-snapshot` marks a full run against
an independent old workspace copy and cannot be cited as the current original-workspace evidence. Final original-checkout runs need an agreed source freeze and must
retain identical complete source/tool/reference input sets throughout.

All61 TCP function obligations and33 original source anchors remain in the actual
copied inventory. This tool promotes no whole TCP function or full subsystem.
The current normal TRANSPORT data/rekey profile, historical normal CORE neighbour
event, and failed/unproved CORE application encryption are separate evidence.
Full shared communicator manager, listener/connect/NAT/reversal/config/persistence,
complete TRANSPORT/CORE, native error profiles and known Peerstore concurrent
shutdown/recovery remain pending. Historical trial3 Peerstore crash, trial6 CORE
application failure, two10/40 stalls and the safe-API authority defect are retained
in their immutable receipts; no new successful receipt relabels those histories.

The current normal reference runner uses the macOS sandbox-exec/otool/lsof profile. Linux/native ABI and reference-runner portability remain separate obligations; embedded Rust checks do not turn that into a Linux C-peer result.
