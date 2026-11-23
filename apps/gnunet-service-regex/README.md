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

## Per-peer policy profiler

The installed `gnunet-daemon-regexprofiler` uses the same REGEX compiler,
PILS signer and DHT publisher. It publishes three rounds through the configured
PILS and DHT endpoints and exits after draining the original operations.
The local `gnunet-service-regex` listener is optional for this workflow.

```ini
[testbed]
PEERID = 0

[regexprofiler]
POLICY_DIR = /absolute/path/to/policies
REGEX_PREFIX = GNVPN-0001-PAD
MAX_PATH_COMPRESSION = 8
REANNOUNCE_PERIOD_MAX = 10 min
```

Run `gnunet-daemon-regexprofiler -c gnunet.conf` from the node's libexec
directory. The peer index selects a zero-based entry in native directory
order, as in the official helper. Use ordinary policy files in a stable
directory. Each row contains a hexadecimal address prefix and may have a
final group of single-digit alternatives such as `abc(0|1)`.
The maximum delay defaults to ten minutes and must fit a positive 32-bit
microsecond value. The first round starts when PILS and DHT are ready.
Subsequent rounds use independent delays below the configured maximum and
reuse the compiled policy. Local completion records whole DHT IPC writes.
