# Conversation interoperability controller

`conversation_daemons.py` runs a private no-audio C-caller→Rust-callee profile.
`--cadet-backend c` uses official C CADET; `--cadet-backend rust` selects a separate
profile with two normal Rust CADET services. Backend selection is explicit and
never a fallback after failure.

## Invocation

```sh
python3 tools/reference/conversation_daemons.py \
  --manifest /path/to/manifest.json \
  --approval /path/to/approval.json \
  --output /tmp/fresh-conversation-evidence \
  --phase no-device
```

For Rust CADET, add `--cadet-backend rust` and use the matching manifest/profile.
The script validates its approval input against the selected manifest, controller
sources, allowed effects and expiry. This file is an execution fence, not proof
of human identity.

## Inputs

The manifest binds native normal C/Rust build indexes, artifacts, configuration
and source receipts. Required C dependencies include the backbone services,
Conversation/GNS/identity services, TCP communicator and record plugins. Rust
provides Conversation service/CLI, GNS CLI and the selected launcher; the Rust
CADET profile additionally binds that daemon.

Build indexes identify revision, native platform, build execution, source hashes,
artifacts and underlying receipts. C indexes also identify linked library/plugin
closure and generated defaults. Artifact kinds are binary, library, plugin or
default; IDs and full required sets are validated by the controller. Missing or
changed inputs fail before participant launch. It performs no build/download/install.

## Runtime and observations

The controller uses private configurations/keys/databases, Unix IPC and two
loopback TCP nodes. It observes real GNS PHONE discovery, caller service dispatch,
callee ringing, cancellation and process teardown. It does not answer a call or
open audio devices. Successful Rust-CADET behavior does not qualify C CADET
peer cryptography, reverse roles or all Conversation transitions.

`conversation_owned.py` owns child processes, streams, deadlines and cleanup.
Output captures, exit/reap facts, artifact checks and independent cleanup failures
are retained in the result. A child exit or local IPC write does not replace the
required protocol observation. Failed profiles remain failed.
