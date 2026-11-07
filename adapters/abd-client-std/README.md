# Native ABD client

One caller-driven standard ABD MQ uses existing EndpointSource/Channel, explicit
shared clock/Resolver and bounded zeroizing framing. No task, service, second
private protocol, implicit Resolver, hidden retry owner or crypto is created. It accepts collect/verify requests, original whole/partial write receipts,
intermediate995 edges and terminal992/994 results with exact original
RID checks. Whole request write precedes response acceptance. A local write is
not service processing or authorization; raw found/status values stay raw.

Initial unexposed connection attempts retain the original source backoff. Once
attached, source loss/cancel/deadline physically retires the MQ and every buffer
before exposing its original cause and receipt. No exposed request or
Collect private key frame is silently replayed onto a new source; no EOF is a
completed negative or positive query. A caller-controlled fresh retry must
retain original hard/canonical bounds and distinguish its new source epoch. Intermediates and result records/frame sizes have explicit finite bounds; only
one incoming frame is observed at a time, with returned storage then owned by
the caller. Private outbound and input frames are zeroizing on every path.

GNS/namestore service composition, normal service/CLI and C
interoperability remain separate work; no whole ABD/goal credit is claimed.

Author non-execution remains unchanged; this is no runtime acceptance.

After attachment the same original RX/TX directions are driven fairly,
including while the request is partially written or native TX is Pending. Independent read EOF/errors are observed without waiting for the write deadline. Expected result/intermediate acceptance still requires the original whole
request. A complete premature frame is refused at its read boundary;
a later TX step cannot promote it. Source retirement snapshots the actual
retained Framed head, including malformed-header bytes omitted by an error-only
read result. Request RID, source, original prefix/whole/unknown facts, fixed
canonical/native targets, record caps and zeroizing ownership remain unchanged.

Four prepared Unix-source cases cover native TX Pending plus peer
write-half EOF, a premature expected complete result, malformed-header4 loss
metadata and a whole request followed by its original matching result. The raw
found1 fixture is a service claim without authorization or proof credit. These
source cases are not native/service acceptance.
