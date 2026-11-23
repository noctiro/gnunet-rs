# GNUnet bootstrap resource container

The SDK builder places explicitly supplied trusted HELLO assets under gnunet/.
No bootstrap peers are included by default. GNUnetBootstrap installs a completed
private generation before the application selects it in GNUnetNodeOptions.
