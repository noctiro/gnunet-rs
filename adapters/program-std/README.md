# PROGRAM host

Shared command preparation, GETOPT, logging, locale, clock and daemon lifecycle
for normal applications. Configuration and arguments preserve native bytes.

- [Public API](API.md): preparation, scoped execution, logging and daemon ownership.
- [Design](DESIGN.md): module boundaries and scheduling policy.
- [Native contracts](NATIVE-CONTRACT.md): process, stream and locale capabilities.
- [Locale inventory](LOCALE-INVENTORY.md): source-specific locale behavior.

A prepared main capability is distinct from option-processing output. Scoped
execution owns bounded tasks; stopping or dropping it retires its work. Process
locale/stderr and daemonization require their documented native capabilities.
