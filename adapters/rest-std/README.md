# Actual REST native handlers and bounded HTTP owner

`Context::new(Instances, Sources, &Idna, Profile, Limits)` takes caller-owned stable native token domains, explicit CLIENT endpoint selectors sharing one RuntimeClock Arc, and the shared IDNA/record producer profile. `Context::execute(OwnedRequest)` consumes an original request. Every execution future owns its own native clients; cancel/drop closes those exact MQ owners, without replay. Local CLIENT Queued/Written events never produce HTTP mutation success. Only service results do. Keys, retained request/body/query/reply bytes and complete response bodies are zeroizing/redacted. JSON output reserves its full configured capacity before copying private data, so growing Vec reallocations cannot leave old private output allocations behind.

handlers:

- IDENTITY GET all/name/pubkey, opt-in `?private` representation, CREATE (explicit imported key or production OS entropy), RENAME, DELETE and raw EdDSA `/sign`. Listing/selection first obtains native START/UPDATE/END initialization. Each selected ego/key is fixed to that original snapshot; no replacement directory can retag it. `/sign` uses the approved existing pure crypto owner's raw method, not a purpose header or production C FFI.
- NAMESTORE filtered GET lookup/iteration, lookup-then-append POST, replace PUT, DELETE and import. Imports preflight all complete sets into one STORE frame before mutation admission; an oversized import is rejected, never silently committed as a prefix. Append strips old serialization padding before concatenating records and has the same read/modify/write concurrency limitation as the official REST workflow. No cross-request transaction or rollback is claimed. Shared `gnunet-gnsrecord-text::Codec` implements all active text families; REST copies no RR text grammar. `Limits::text_bytes` is separate from native frame/body storage, so long textual TLSA/CERT-like results can fit the explicit output budget.
- RECLAIM attributes and credentials GET/POST/DELETE, ticket enumeration, revoke and consume. Attributes use exact Unicode18 lowercase/NFD via the shared pure helper. JWT-derived fields/attributes use the shared credential parser with explicit Unverified assurance. Active credential POST is JWT; inactive PABC semantic/proof support is not manufactured. Missing/zero IDs are left to service assignment as supported by the official producer. Ticket streams accept native pushes; attribute/credential streams grant NEXT only after items. Consume retains its raw status in Response/HTTP Report metadata, including the known C producer byte-order defect; it does not normalize a status into an ACK. Only a successful result from the explicitly selected RECLAIM producer with the exact original ticket issuer produces an attribute body. A denial is HTTP403; a provider failure, unknown word or issuer mismatch is HTTP502. Every raw result survives Response/HTTP Report metadata, including error responses. It does not verify issuer signatures, audience or trust.

- Actual static GET/copying and OPTIONS for connected namespaces.

RECLAIM subject names are matched byte-for-byte against the original directory. GET/POST and ticket listing use the complete route suffix as the name. Attribute/credential DELETE uses the first two nonempty slash tokens as subject
and ID; later tokens are unused, matching the pinned plugin. Path requirements
are checked before client construction or directory work. A longer ego name
containing `/` cannot replace the DELETE subject selected by its first token.

An unknown read/delete subject returns `[]` with HTTP200 before ID decoding. Missing required path parts retain HTTP400. Unknown POST subjects return the
existing bounded HTTP404 error. The pinned C POST branch instead logs and returns
without generating a response, with an infinite plugin timeout; that behavior is
not reproduced. Known-subject ID/body validation and mutation results
retain their original paths. Directory, native and backend failures propagate.

`http::Server::new(&Context,&Policy,Limits,ServiceOptions,UnixAccess)` owns a finite accepted-connection pool. Caller supplies shared listeners and drives Resolver separately. `admit`, `poll`/`drive`, `request_shutdown`, `close_all` are callable. Each connection retains one original HTTP RX/TX cursor and one request future; canceled drive observations preserve it. One connection serves one response with Connection:close. Total logical/native request deadlines are fixed at acceptance, before body/native work. A finite send target is fixed before first output write and capped by the original total bound. Native hard alarms are polled before canonical-clock waits, so revision races cannot prevent expiry. Explicit clock failure independently drops every host job before returning. Owner close/cancel requires no clock sample. Drop-based socket close has no independent close(2) errno receipt and is not a remote rollback acknowledgement.

Basic authorization and CORS are explicit caller policy, checked before any backend admission.

`http::Policy { authorization, cors }` takes an immutable `http::Cors::new(allowed_csv, echo_webext, credentials, allowed_headers)` policy. CORS configuration is bounded to4096 bytes and64 trimmed comma-separated origins; Credentialed wildcards are refused. Empty or invalid entries and invalid response-header values are also rejected. Full origin tuples match exactly (case-insensitive scheme/host, effective port), including bracketed IPv6 and explicitly allowed null; no prefix or suffix matching occurs. The explicit extension option permits valid moz-extension/chrome-extension origins. Duplicate/malformed request Origin is refused before backend work. Dynamic origin selection emits Vary: Origin even when no rule matches. The CORS owner keeps one bounded configuration byte arena plus origin ranges; request handling allocates only the one selected response origin.

Unix UID/GID and TCP ACL use shared SERVICE machinery. A read FIN after a complete request is only a write-half-close and does not cancel a valid waiting client; reset/read errors, write errors, explicit cancellation or original expiry retire the owner. Pending waits have native I/O, canonical subscription and native hard timer wakers. No tasks, Resolver, daemon, service/WAL/database or hidden retry loop is created by the library.

CONFIG/GNS/forms/conditional OIDC use the explicit capabilities described below. The pinned active HTTP daemon does not enable its dormant HTTPS settings; a Connection:close response is valid HTTP/1.1 behavior. Canonical key Base32 is accepted; malformed/nonzero padding and ambiguous queries are refused rather than reproducing unsafe C behavior. REST status/error handling preserves service codes and original typed source/local-retirement causes; not all C error hints are reproduced byte-for-byte. Default output/JSON/item/text budgets can reject otherwise larger valid results.

## CONFIG and explicit GNS query source

`Context::with_configuration(&config::Port)` connects official CONFIG GET/POST. `config::Driver::start(live, explicit_output, original_clock, limits)` starts one explicit bounded file worker. Foreground polls it alongside HTTP/Resolver and drains/joins it during shutdown. The shared Configuration parser/setters/serializer and approved `write_serialized` atomic writer own the INI format and publication path. A successful original file close/atomic writer and parent-directory sync precede visible `LiveConfiguration::replace` and HTTP200. An admitted callback dropped by HTTP is still consumed by Driver; original publication is never replayed. Original generation/Job/native+logical bounds, owned parent/target/lock identities and finite queued bytes are retained. Shared writer errors conservatively become Unknown because that API does not expose a publication-stage or temporary-cleanup receipt; Unknown blocks new operations and survives the dropped callback. Existing serializer behavior (installation PATHS omission, LF rendered as literal backslash-n without parser unescaping) is retained rather than replacing the configuration foundation. INI section/key injection is refused. A dispatched filesystem syscall requires OS progress; a timeout cannot prove it did not publish, and joining that original worker can wait for the kernel.

`Context::with_gns(&gns::Gns)` uses the already implemented external native GNS query client. No resolver/service/recovery backend is added. Each query owner/Instance is local to that original request. Selection follows the public with-TLD API: direct typed zTLD, longest configured `[gns] .suffix` mapping, then IDENTITY suffix lookup with the official local options. Actual GNS records use shared text/JSON. Zero records give an empty data array; a name outside GNS gives404. No response/loss is promoted to success or replayed. Whole HTTP hard expiry may physically close the connection before an error response can be written.

Every request freezes grouped EndpointSources before any native admission, including IDENTITY directory lookup. Sources sharing one LiveConfiguration derive from ONE original configuration copy. All phases duplicate these fixed selectors; CONFIG cannot rebind an old subject to a different service. Clock Arc and process Resolver port remain the originals; a selector snapshot is neither a DNS answer nor a connection epoch. Public Context constructors still require explicitly attached capabilities, and never manufacture readiness.

## Conditional OIDC

The pinned Meson build includes openid_plugin.c/oidc_helper.c only when JOSE exists; pabc_plugin.c is unbuilt. The Rust `oidc` feature connects `oidc::Provider` and authorize/login/token/userinfo handlers, GET discovery, and GET `/jwks.json` outside `/openid`. `Provider::new` accepts an explicitly owned real `Signer::{Rs256,Hs512}`, original clock, origin/login UI, optional confidential-client secret, explicit consume-status profile and bounded state pools. It reads no key path, spawns no task, and silently downgrades no algorithm. RS256 uses the approved mature non-FIPS native/asm AWS-LC primitive through gnunet-oidc-crypto-host; it is not claimed as a pure Rust RSA primitive or FIPS backend. HS512 reuses the existing zeroizing HMAC512 primitive.

Authorize checks GNS redirect registration by exact value, initialized IDENTITY subject, RECLAIM attribute iteration and ticket/presentation issuance before signing purpose27. Normal STRING claims and opaque aggregated JWT presentations remain distinct; presentation authenticity belongs to the relying party. Login Identity cookies are bounded original three-second sessions (the active C constant is3, not its stale30-minute comment). Standard scope groups, exact nonstandard scope names and named id_token/userinfo claims select attributes. For example, `scope=openid%20department` selects the actual `department` attribute for both ID token and userinfo, including its aggregated presentation when applicable. Scope tokens follow RFC6749 section3.3 ASCII syntax; unknown well-formed names contribute no invented attribute or rejection. The `openid` control scope and empty split items do not select same-named attributes; explicit named claims remain available. Only original RECLAIM iteration results enter ticket issuance; claim values, including essential/value/values, are ignored as in the active producer. Token authentication uses configured client credentials plus local confidential identity, or public-client S256 PKCE. Signature verification derives the issuer only after decoding the original ticket. Original client ID, redirect URI, one-use code, native+logical expiry and purpose signature are checked. After GNS registration validates the exact callback, explicit OAuth authorization errors return `error`, `error_description` and the original `state` through that bounded percent-encoded callback. Missing or unregistered client/callback authority never produces this redirect. Independent source, IO, clock, cryptographic and resource failures retain their typed causes. Cached authority never retags a replacement MQ. Userinfo always consumes the ticket and checks its identity/status; no speculative old-attribute cache fabricates a successful result. The raw consume word is retained in Response/Report; canonical BE32 or pinned little-endian C producer defect is one explicit RECLAIM source profile shared with ordinary REST, never auto-detected. An matching-issuer GNUNET_NO becomes UserInfo401 invalid_token with a Bearer challenge. A provider failure, unknown result, mismatched issuer, source loss or timeout preserves its independent cause and does not claim revocation. Token-endpoint invalid_client401 carries Basic; challenges are selected by their OAuth flow and never inferred for unrelated/global401 responses.

HTTP URL-encoded and multipart forms are bounded/preflighted, duplicate parameters across query/body fail, and only original content-type/auth/cookie fields survive erased RX into the handler. Original cookies/location/cache-control fields have owned zeroizing values. Global HTTP Basic is a separate envelope: after it authenticates, that same header is not reinterpreted as OAuth client credentials. Client-secret POST and access_token parameter work with that envelope; OAuth Basic/Bearer headers require explicit global-Basic-disabled policy. The origin/login UI and signer are fixed until restart, while new native jobs can observe committed CLIENT configuration. Standard public JWKS is `{keys:[...]}` rather than the C route's bare-JWK bug; HS512 publishes no secret key. C issuer-before-copy, redirect-prefix, short PKCE and URI-hyphen bugs are not reproduced.

Explicit `Provider::persistent` claims only a new or Rust-OIDC-marked private directory, restores the original owned RSA PKCS8/HS signer and live issued grant/access artifacts, and returns its independently polled single `persistence::Driver`. The foreground requires explicit `OIDC_STATE_DIRECTORY` and waits for initial commit before readiness. The existing `Provider::new` remains an explicitly ephemeral embedding constructor. Signer replacement after recovery failure, C JWK/store adoption, key rotation and refresh-token routes are not provided; PABC proofs remain unavailable in the active build. Claim selection uses requested names as in the active C producer. Address subfields preserve its first normal/aggregated mode, first matching presentation and original source indices; conflicting later modes are skipped. Whole address claims and normal structured address/subfields are supported.

The default `canonical` consume profile accepts the BE32 success word `1`. For the pinned little-endian C RECLAIM producer, explicitly select `OIDC_CONSUME_STATUS_PROFILE=c-native-little`: its `uint32_t` field is assigned with `htons(1)`, producing bytes `00 01 00 00`, preserved by the IPC decoder as `0x0001_0000`. That profile accepts this exact success word and recognizes SYSERR only as raw0xffff_0000; canonical SYSERR is0xffffffff. Both profiles recognize NO=0, but neither accepts the other profile's success/failure words. Context owns this choice for both REST and OpenID; the server reads the same configuration even when OpenID is disabled. Userinfo retains the original raw status, returned subject binding and original expiry checks.

### OIDC durable ownership

The OIDC namespace uses the shared qualified snapshot backend/one disk worker with private permissions, exclusive lock, nofollow/link/ownership checks, atomic replace+file/parent sync receipts and independent known/unknown publication errors. An existing marked root with a missing canonical image fails closed; only the backend's actual `created_directory()` fact and generation0 permit first key generation. Authorize and token exchange stage one finite immutable snapshot; only its original worker completion changes canonical issued state and permits a successful HTTP response. Foreground polls this owner independently of dropped request futures and drains/joins after HTTP shutdown. Incomplete/uncertain persistence latches issuance rather than replaying it.

Private RSTOID02 snapshots retain opaque signer material, exact configured signer/issuer/login/client-secret domain, original expiry/wall expiry, bounded Issued grants and accesses with one-use exchanges. The RECLAIM source-status profile, login sessions, Reserved rows, native/HTTP scopes and callbacks are never serialized. Older private RSTOID01 images are refused, without compatibility migration. Recovery reconstructs a finite hard bound from remaining original source and wall targets, rejects observed time rollback, and never resets TTL. Actual userinfo still consumes the original RECLAIM ticket; persisted access/code data is not a fabricated RECLAIM result. Fresh authorization can reissue an identical deterministic bearer in its existing bounded slot.

### Original NAMESTORE path subject

NAMESTORE selects the original initialized directory's ego by the first path
segment, with the active plugin's ASCII case-insensitive comparison. A longer
identity containing slashes cannot replace that zone. GET and DELETE use the
remaining suffix as their record label; POST, PUT and import use their validated
body record labels and do not let an unused path tail choose another ego. A missing segment is refused before constructing the directory client. Missing
or unknown zones use NAMESTORE error5002 and its existing HTTP404 mapping rather
than the IDENTITY error200. Empty leading zone segments stay refused; C's
repeated-leading-slash pointer-offset accident is not reproduced. The selected
private key remains the original directory snapshot, and lookup/STORE,
reply, cancellation and Unknown handling are unchanged.

Direct `Context::execute` captures its finite native hard target before the
external canonical-clock sample. Time spent obtaining that sample therefore
cannot extend the original native budget; the same native alarm is polled before
any request work. Original clock errors, logical coordinates and inner-future
retirement remain separate. The HTTP server's acceptance-bound owner remains
the outer request limit.

### Normal upload100-continue

The existing one-request HTTP owner accepts the standard `Expect:100-continue`
handshake for ordinary bounded REST bodies (including normal JSON POST/PUT). One shared pure `RequestHead` parser validates the original method, target,
headers, framing and known length before body waiting. Original Basic policy,
CORS and route admission run before interim output;401/404/405 and known
oversize413 can therefore finish without inviting the body. OPTIONS reuses the
same synchronous handler decision before body waiting or100: actual200, or
original OpenID capability501. Successful OPTIONS supplies the permitted
Access-Control-Allow-Methods as well as Allow, with the existing origin and
configured header response policy. Like the normal C plugin, it does not invent
an extra HTTP403 admission test for browser-requested method/header fields;
browsers apply those original response fields. Unknown or mixed
expectations produce417, including the ordinary final Connection:close. Repeated known100-continue members mean one expectation, not repeated replies. Known100-continue on HTTP/1.0 is ignored; a zero/no-body request or one with
already received body bytes gets no interim100.

When required, only the exact25-byte `HTTP/1.1 100 Continue\r\n\r\n` prefix
is written, preserving its original partial cursor. The complete interim write
precedes any further body read. Its finite send target is capped by the
acceptance-bound original hard target; the same outer logical/native request
limits continue through header, interim, body, backend and final response. No target is renewed and no temporary source/task/ACK/native operation exists. `Report.continue_written` retains interim partial/whole bytes separately
from final `status`/`written`. A failed interim write closes the original source
without suffix replay or backend admission. Full body framing and all existing
mutation/result/cleanup rules still apply. Pipelined suffixes remain outside the
one selected request and never invoke another handler on this connection.

The source contract is the fixed GNUnet REST MHD first-call/upload path and
its installed MHD1.0.10 normal CONTINUE_SENDING state, plus RFC9110 section10.1.1. The selected normal HTTP runs did not exercise `Expect:100-continue` or its
failure paths.
