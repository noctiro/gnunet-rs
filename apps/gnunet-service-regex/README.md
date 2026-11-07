# gnunet-service-regex

The ordinary installed SERVICE entry uses `NativeFactory`: the bounded
REGEX Core/IPC server, purpose-18 PILS signing, one DHT client/reader,
shared Resolver/clock and official STATISTICS. Standard configuration, logging,
USERNAME, activation/parent control, daemon readiness and owned shutdown come
from the shared SERVICE frontend. No private wire, libgnunet backend, mock
publication, hidden runtime or detached worker is added.

Search GETs remain persistent across safe readonly DHT reconnect with the same
logical query. Local PUT whole-writing is observed once and never means remote
storage; an uncertain PUT is not replayed. Original registration/STOP/PUT and
partial-input native phase bounds remain finite and separate from search life.
