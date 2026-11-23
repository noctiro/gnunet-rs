# gnunet-cli

Commands for GNUnet service IPC and local FS operations.

```sh
cargo build -p gnunet-cli --locked
gnunet-cli --help
```

The [command reference](commands.md) contains examples, configuration selection,
JSON fields and completion/error behavior for STATISTICS, FS, NAMESTORE,
IDENTITY, VPN, REGEX and TRANSPORT.

The `statistics` feature also builds [gnunet-statistics](commands.md#statistics).
The `identity` feature builds [gnunet-identity](commands.md#identity-keys).
The `namestore` feature builds [gnunet-namestore](commands.md#namestore-delegation-import)
for GNS URI import and [gnunet-namestore-zonefile](commands.md#namestore-zone-files)
for zonefile import.
The `fs` feature builds the [installed file-sharing commands](commands.md#installed-file-sharing-commands).
The `regex` and `revocation` features build the installed
[gnunet-regex](commands.md#regex) and [gnunet-revocation](commands.md#revocation) commands.
The `did`, `transport` and `vpn` features build the installed
[gnunet-did](commands.md#did), [gnunet-transport](commands.md#transport-monitoring)
and [gnunet-vpn](commands.md#vpn) commands.
The `reclaim` feature builds [gnunet-reclaim](commands.md#reclaim).

An explicit socket path selects that service endpoint. Commands supporting `-`
resolve the endpoint from normal configuration. Service commands require a
listening service; local FS/crypto operations use their documented local inputs.

## Command features

The default build includes all command groups. Each group also has a Cargo
feature with its command name, such as `statistics`, `fs` or `identity`. Help
lists the selected groups. A focused build admits only its client dependencies:

```sh
cargo build -p gnunet-cli --no-default-features --features statistics --locked
```

STATISTICS and TRANSPORT share native parent capture, stop subscriptions and
stdout progress through `foreground/`. Command modules retain their protocol,
JSON encoding and original cursors. Windows output has one bounded submission at a time;
only actual flush advances the confirmed cursor. An outstanding OS write at
stop or deadline remains an output error, with no completed-row claim. Runtime
shutdown does not wait indefinitely for its blocking stdout worker; the normal
command then exits its process. It does not claim that the write was canceled.
FS output uses [PROGRAM's bounded owner](../../adapters/program-std/src/output.rs):
a reusable 64 KiB buffer, capacity-one admission and one native write job.
Rows count as emitted only after actual write/flush. Work output keeps the original
operation deadline; terminal output has one fixed five-second cleanup grace.
Native stop, deadline and output failures retain pending I/O and confirmed byte
prefixes without starting a replacement write. Diagnostics use independently
bounded stderr; `fs cat` preserves arbitrary bytes on its original stdout route.

FS commands share their native path and protocol-text boundaries, private
publication peers and stop-event handling across Windows and Unix. The `fs`
feature includes its runtime dependencies and also builds independently. Native
platform qualification is tracked in [implementation status](../../IMPLEMENTATION_STATUS.md).

Protocol name arguments retain Unix bytes. On Windows they require Unicode and
enter the wire as UTF-8; isolated native surrogates are rejected. Filesystem paths
keep their separate native representation, including attached `--output=PATH`
options. FS JSON byte fields use the local native codec; they are not GNUnet wire
encodings. A stopped operation retains its original future through settlement,
and stop-source errors remain separate from operation and output errors.
Key generation uses the native CSPRNG
boundary rather than a Unix device path.

Streaming output may precede a failure. Require exit zero and the command's
terminal completion event. Timeouts, local writes and empty observations are not
remote acknowledgements or not-found results. Mutations with unknown outcomes
are not automatically replayed.
