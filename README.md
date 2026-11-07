# gnunet-rs

An independent Rust implementation of GNUnet, targeting its full feature set and
interoperability with official C nodes, clients and services. Protocol and service
logic are implemented in Rust; official C software is used for reference checks.

**Development is incomplete.** See [implementation status](IMPLEMENTATION_STATUS.md)
for functionality and interoperability work that remains.

## Getting started

Run commands from the repository root. Rust is pinned by
[rust-toolchain.toml](rust-toolchain.toml); native features may also require a C
compiler and platform SDK.

Native services target Unix. Windows CI covers the portable core; embedded
profiles compile selected `no_std` configurations. See the
[platform matrix](tests/README.md#continuous-integration) for execution scope.

Build the CLI and inspect its commands:

```sh
cargo build -p gnunet-cli --locked
cargo run -p gnunet-cli --locked -- --help
```

The [CLI guide](apps/gnunet-cli/README.md) covers service endpoints and output
semantics; its [command reference](apps/gnunet-cli/commands.md) contains examples.
Service commands require the corresponding service to be running. Local file and
crypto commands use their documented local inputs.

## Rust library

The [gnunet facade](crates/gnunet/README.md) exposes protocol engines and optional
native adapters. Default features are empty and the default library is `no_std`.
Select only the capabilities needed by an application:

```sh
cargo check -p gnunet --no-default-features --locked
cargo check -p gnunet --features official-ipc --locked
```

See the [SDK guide](crates/gnunet/README.md) for feature selection and API paths.

## Service processes

Each executable has a guide under [apps/](apps/) covering configuration and
runtime dependencies. For example, [STATISTICS](apps/gnunet-service-statistics/README.md)
accepts an official configuration file:

```sh
cargo run -p gnunet-service-statistics --locked -- -c /path/to/gnunet.conf
```

From another terminal, query its configured Unix socket:

```sh
cargo run -p gnunet-cli --locked -- statistics get /path/to/statistics.sock
```

Starting one service does not start its dependencies or a complete node stack.

## Development

| Guide | Contents |
| --- | --- |
| [Architecture](ARCHITECTURE.md) | Dependency direction, ownership and resource rules |
| [Protocol contracts](spec/gnunet/README.md) | Compatibility boundary, reference authority and release criteria |
| [Test guide](tests/README.md) | Targeted checks, full matrix and official-C profiles |
| [Security](SECURITY.md) | Vulnerability reporting and supported scope |
| [Implementation status](IMPLEMENTATION_STATUS.md) | Open functionality and acceptance work |

## License

[MPL-2.0](LICENSE). Bundled data and third-party dependencies retain their own
licenses; see [third-party notices](NOTICE.md).
