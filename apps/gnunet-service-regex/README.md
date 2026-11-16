# gnunet-service-regex

The ordinary installed SERVICE entry uses `NativeFactory`: the bounded
REGEX Core/IPC server, purpose-18 PILS signing, one DHT client/reader,
shared Resolver/clock and official STATISTICS. Standard configuration, logging,
USERNAME, activation/parent control, daemon readiness and owned shutdown come
from the shared [SERVICE frontend](../../adapters/regex-program-std/).

## Configuration and startup

The native entry supports Unix and Windows using the shared
[startup contract](../../adapters/program-std/README.md#service-startup).
`[regex]` selects local/TCP listeners; `[PILS]`, `[dht]`, `[resolver]` and
`[statistics]` select dependencies. See the frontend for resource limits and
PILS profile selection.

```sh
gnunet-service-regex -c gnunet.conf
```

Readiness requires the verified PILS identity and the original DHT provider's
local readiness predicate. Native or parent-control stop requests and selected
logging failure drive the same owned shutdown. Windows verifies the configured process identity;
explicit Unix UID/GID admission is unsupported there.

## Operation lifetime

Search GETs remain persistent across safe readonly DHT reconnect with the same
logical query. Local PUT whole-writing is observed once and never means remote
storage; an uncertain PUT is not replayed. Original registration/STOP/PUT and
partial-input native phase bounds remain finite and separate from search life.
