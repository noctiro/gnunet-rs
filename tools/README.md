# Development tools

Run development tools from the repository root. Generated logs, transcripts,
build receipts and performance results belong under `target/`.

## Checks and tests

The [test guide](../tests/README.md) documents `cargo xtask verify` groups and CI.
[xtask](xtask/src/) owns workspace, dependency and feature checks.
`python3 -B tools/check_tools.py --list` lists Python tool controls.

## Official reference software

[Reference programs](reference/README.md) document isolated official C builds and
interoperability profiles. [API inventory tools](api_inventory/README.md) extract
reference interfaces. [External contract tools](external-contracts/README.md)
maintain operation and evidence data under [spec/gnunet](../spec/gnunet/README.md).

## Performance

The [framing harness](performance/framing/README.md) records comparable framing
measurements. Measurement scope and reproduction inputs belong with each runner;
results remain generated artifacts.
