# Implementation status

This page tracks functionality and interoperability gaps. Implement Android,
iOS and OpenHarmony first. The remaining items are ordered by user impact and
dependent workflows. Items marked **upstream C** require an upstream change.

## Reference target

- GNUnet v0.29.1 baseline at `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.
- Selected upstream C revision
  [`7e0f9c3640310fd406fcf32c271ab583ef83d6c9`](https://git.gnunet.org/gnunet/gnunet/commit/7e0f9c3640310fd406fcf32c271ab583ef83d6c9.html).

The reference scope includes installed services, plugins, commands, helpers,
active contrib components and public behavior. The [public API inventory](spec/gnunet/api/README.md)
and [operation map](spec/gnunet/external/operation-entrypoints.json) support
the comparison.

## Known limits

- **NAT-AUTO client routing (upstream C).** The selected C API connects to
  `nat` for the configuration request, but only `nat-auto` handles that
  message. Route the client to the separate NAT-AUTO endpoint to use the
  official request and response.
- **Apple DNS Proxy site-local TCP.** NetworkExtension exposes the original
  interface but no TCP local endpoint for qualifying legacy IPv6 site-local
  zones. The proxy refuses those flows.
  [Apple DNS backend](adapters/dns-service-std/NATIVE_BACKENDS.md#apple-provider-path)
- **CADET encrypted channels (upstream C).** The receiver selects the wrong
  header tag, inverts the next-header success check and includes the detached
  payload tag in the ciphertext length. This blocks encrypted CADET traffic
  with the selected C peer and affects Messenger, Conversation and VPN/EXIT.
- **DHT monitor selectors (upstream C).** The selected C daemon ignores the
  requested event flags, skips matching exact keys and compares monitor STOP
  flags in their raw wire order. These defects affect filtered subscriptions
  against the C service.
  [C monitor dispatch](https://git.gnunet.org/gnunet/gnunet/file/src/service/dht/gnunet-service-dht_clients.c.html#l1735)
- **DHT approximate cache replies (upstream C).** For an approximate GET that
  requests a type other than DHT_HELLO, the selected C daemon can reply to a
  cache hit with the actual block key in the query-key field. A reverse lookup
  waiting on the original query key cannot correlate that reply.
  [C cache reply](https://git.gnunet.org/gnunet/gnunet/file/src/service/dht/gnunet-service-dht_neighbours.c.html#l2430)
- **REGEX announcements with multiple accepting records (upstream C).** The
  announcement iterator cancels the previous pending PILS signature when it
  reaches another accepting record. Only the last requested signature can
  produce a REGEX_ACCEPT block in that pass.
- **FS retrieval (upstream C).** Downloads use inconsistent AEAD lengths and
  tag offsets. Search can misread plaintext metadata lengths, stop before later
  DATASTORE rows, attach a continuation to the wrong query or repeatedly send
  the same SKS continuation after reconnect. The CORE GET checker rejects
  serialized UBLOCK Bloom hints because it counts the nonce as filter bytes.
  [FS source contract](crates/gnunet-fs/UPSTREAM.md#content-block-and-bounded-tree-format) ·
  [GAP wire behavior](adapters/fs-std/API.md#serving-and-routing)
- **DNS interception.** Raw helper/TUN framing carries no IPv6 zone. Linux local
  `OUTPUT` needs original socket and zone ownership, and TPROXY reply
  submission cannot pin the interface across replacement. FreeBSD lacks
  capture and delivery that preserves the original receiving socket and zone.
  Windows receive injection still uses interface indices. WinDivert and the
  WFP receive gate cannot pin the original interface across replacement.
  [Native backends](adapters/dns-service-std/NATIVE_BACKENDS.md) ·
  [WinDivert](adapters/native-std/WINDIVERT.md#packet-metadata-and-injection) ·
  [WFP package](platform/windows/wfp-driver/README.md#package-preparation)
- **DATASTORE object publication recovery.** An interruption between creating
  the final hard link and removing the staging link can leave both names.
  Orphan collection currently requires a single link and cannot retire this
  pair. Use exclusive rename where available or recover a verified staging
  alias tied to the object's UID.
- **NAMESTORE apex nicknames (upstream C).** C drops ordinary apex NICK records
  before persistence and from apex reads. Supplemental copies at other labels
  rewrite the original flags and expiration.
  [Command reference](apps/gnunet-cli/commands.md#namestore-administration)
- **NAMESTORE reverse misses and editor replies (upstream C).** The C client
  asserts on the service's keyless reverse-lookup miss and rejects an absent
  previous editor hint. The C service serializes editor-cancel failures with
  a 16-bit conversion into a 32-bit field.
  [C client](https://git.gnunet.org/gnunet/gnunet/file/src/service/namestore/namestore_api.c.html#l524) ·
  [C editor cancel](https://git.gnunet.org/gnunet/gnunet/file/src/service/namestore/gnunet-service-namestore.c.html#l1491)
- **Windows socket activation and UNIX datagrams.** A bare AF_UNIX transfer
  cannot establish which access checks governed the listen queue. Windows
  lacks the AF_UNIX datagrams required by the UNIX communicator.
  [Windows identity](adapters/service-startup/README.md#windows-identity) ·
  [Activation](adapters/native-std/SOCKET-ACTIVATION.md#local-endpoint-access) ·
  [UNIX communicator](adapters/unix-communicator-std/README.md#wire-format-and-platform-constraints)
- **Generic SET (upstream C).** UNION can expose later insertions through a
  lazy copy and ignores `FORCE_DELTA`. INTERSECTION emits zero result sizes
  and writes element types in host byte order. [SET contract](crates/gnunet-set/README.md)
- **GNS delegation (upstream C).** GNS2DNS rejects co-located security records
  permitted by RFC 9498. The NAMESTORE URI importer writes a typed key where
  the delegation resolver expects the key payload alone.
  [GNS provider](adapters/gns-service-std/API.md#ordinary-auxiliary-dependencies) ·
  [RFC 9498](https://www.rfc-editor.org/rfc/rfc9498.html#section-5.2.2) ·
  [Delegation import](apps/gnunet-cli/commands.md#namestore-delegation-import)
- **REVOCATION recovery and reconciliation (upstream C).** The selected C
  daemon persists only the fixed header of an accepted revocation message.
  Its SETU receiver also rejects elements carrying the full proof.
  [C revocation service](https://git.gnunet.org/gnunet/gnunet/file/src/service/revocation/gnunet-service-revocation.c.html#l373)
- **VPN/EXIT gateway selection and named-service ICMP (upstream C).** The C VPN
  selects the gateway using the local lease family even when the target has a
  different family. The C EXIT compares a network-order ICMP service AF with
  host-order constants and rejects the request on little-endian systems.
  [VPN gateway selection](https://git.gnunet.org/gnunet/gnunet/file/src/service/vpn/gnunet-service-vpn.c.html#l1418) ·
  [EXIT ICMP handling](https://git.gnunet.org/gnunet/gnunet/file/src/service/exit/gnunet-daemon-exit.c.html#l2308)
- **EXIT UDP forwarding (upstream C).** The C EXIT writes the payload length
  into the UDP length field. Both Internet and named routes index the reply
  tuple before overriding the requested source port, so the emitted tuple can
  differ from the lookup key.
  [UDP header](https://git.gnunet.org/gnunet/gnunet/file/src/service/exit/gnunet-daemon-exit.c.html#l814) ·
  [Internet handler](https://git.gnunet.org/gnunet/gnunet/file/src/service/exit/gnunet-daemon-exit.c.html#l1565) ·
  [Named service handler](https://git.gnunet.org/gnunet/gnunet/file/src/service/exit/gnunet-daemon-exit.c.html#l1627)
- **PT DNS forwarding (upstream C).** The C daemon removes each new DNS
  request from its reply queue before insertion. Its response handler also
  fails to return CADET receive credit, blocking later replies on that channel.
  [Request handler](https://git.gnunet.org/gnunet/gnunet/file/src/service/pt/gnunet-daemon-pt.c.html#l794) ·
  [Response handler](https://git.gnunet.org/gnunet/gnunet/file/src/service/pt/gnunet-daemon-pt.c.html#l866)
- **FS publication metadata.** RAW extraction still needs additional Nikon
  MakerNote layouts and Samsung Type 2 variants.
  Minolta RD-175 MDC and Kodak C330 YRGB need format evidence beyond filenames
  and file sizes.
  [RAW samples](https://www.rawsamples.ch/index.php/en/)
  IIM still needs further ISO 2375 graphic sets and device-dependent ISO 6429
  layout controls.
  [FS extraction](adapters/fs-std/API.md#metadata-and-automatic-keywords)
- **SECRETSHARING.** General multiparty `780→783` remains unavailable. The
  fixed FAIR fields lack a general construction within the nonce, response
  and recovery ranges. The selected C verifier also rejects the correct
  Paillier proof equation. [FAIR construction](crates/gnunet-secretsharing/README.md#fair-construction)
- **Windows crash durability.** Anchored directory owners request the native
  barrier on local NTFS. The native directory barrier remains unavailable on
  remote and other filesystems.
  [Publication contract](adapters/native-std/API.md#anchored-filesystem-operations)
- **CONSENSUS results (upstream C).** The service grades ECHO votes and selects
  the last ECHO output. It can return locally inserted values or abort on client
  disconnect during final iteration. [Grading contract](crates/gnunet-consensus/README.md#grade-and-result-decisions)
- **Messenger authorization (upstream C).** The receiver attempts AEAD
  decryption without reconstructing the tag omitted from the 192-byte record.
  [Authorization contract](crates/gnunet-messenger/README.md#authorization-constraint)
- **OpenID Connect key discovery (upstream C).** The optional `/jwks.json`
  endpoint returns one bare JWK. Standard clients expect a JSON Web Key Set
  with a `keys` array. [OpenID Connect contract](adapters/rest-std/API.md#conditional-oidc)
- **TESTING netjail configuration (upstream C).** The helper's zero-based
  topology lookups can miss one-based carrier and subnet overrides.
  [TESTING command helpers](adapters/testbed-std/README.md#testing-command-helpers)

## Extensions

Full macOS mDNS interception on UDP port 5353 needs its own capture and
original-socket delivery mechanism. The selected upstream DNS service uses
port 53. [Apple DNS backend](adapters/dns-service-std/NATIVE_BACKENDS.md#apple-provider-path)

A native semantic RECLAIM PABC provider remains open. The selected upstream
build installs BASIC attributes and JWT credentials.
[Credential provider](crates/gnunet-reclaim-credentials/README.md)

## Release acceptance

Use the [test guide](tests/README.md) for runtime coverage and the
[external release criteria](spec/gnunet/external/RELEASE.md) for required evidence.
