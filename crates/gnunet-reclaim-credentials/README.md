# Bounded RECLAIM credential helpers

Pure callable Rust helpers for the ACTUAL v0.29.1 plugin build. Default is
no_std/noalloc. `presentation(Credential, AttributeList) -> Result<Presentation,
Failure>` is ready for the ticket core's original effect/provider completion:
it returns a borrowed full JWT payload with the original credential ID and type;
the caller's existing bounded Pool can make the one final owned copy. No source,
operation, TTL, durability, signature validity or successful ticket is invented.

Pinned build facts:

- `src/plugin/reclaim/meson.build` builds BASIC STRING and JWT. It does not build
  the present PABC C source or supply libpabc/helper parameters/user contexts.
- JWT extraction selects the second nonempty dot-delimited C-string segment,
  base64url-decodes it, and parses JSON. It NEVER inspects a JWT header or verifies
  a signature. `iss` is just a string and `exp` is just an integer field. The
  plugin grants no issuer authenticity. Authenticity must come from an explicit
  external verifier/trust policy or a caller's already trusted original source;
  NAMESTORE/GNS publication provenance alone is not a JWT issuer signature.
- Attribute extraction skips exact lowercase iss/jti/exp/iat/nbf/aud, flattens one
  object-valued address level, skips nonobject address, and keeps all other JSON
  types. Plugin attribute construction lowercases/NFD-normalizes names. IDs,
  credential reference and flags of those newly extracted attributes begin zero.
- JWT presentation ignores selected attributes and copies the ENTIRE original
  payload, not a selectively disclosed subset. The library wrapper sets its
  credential_id to the original credential ID. This Rust path does exactly that
  with a borrow; copying is deferred to the caller's immutable owner.
- PABC source text conversion is still a trivial string copy plus NUL. Its
  OPTIONAL semantic plugin would call external libpabc and load issuer parameters
  and a user's private context for proof generation. This pin does not build it.
  No fake JSON/PABC schema, proof or validation implementation is substituted.

Callable functions/types:

- `attribute_from_string`, `credential_from_string`, type-checked
  `attribute_value_string`/`credential_value_string`, public source type-name
  helpers and `value_string`: BASIC/JWT/PABC byte/C-string conversions.
  New input strings exclude NUL; output includes it as the plugins do. Existing
  value views stop at the first NUL as strndup(data,data_size) does. PABC text
  conversion does not make its inactive semantic provider available.
- `Workspace::new(payload, tokens, nesting)`, then `credential`, `presentation`
  or `parse(kind, Sensitive, Limits)`: no hidden allocation. The workspace owns
  exclusive caller buffers; initialization, each error and Drop erase ALL decoded
  payload/token/nesting storage. Live Claims/views prevent safe-Rust reuse/drop.
  Original input/output ownership remains explicit; input is not erased through
  an immutable borrow. Metadata has redacted Debug and carries offsets only.
- Complete JSON object/array/string/number/bool/null grammar, UTF-8 and escaped
  surrogate-pair validation; caller node/nesting/work quotas. Parser nesting is
  iterative. Duplicate decoded keys are deliberately rejected with Conflict;
  comparison work is budgeted. No partially parsed/empty-success list is returned.
  Maximum depth64 also bounds formatter recursion. All scalar/nested claim values
  remain available as borrowed JsonValue, not a scalar-only demonstration.
- `Claims::{attributes,lookup,issuer,expiration,expose_payload,assurance}` plus
  decoded `JsonString` views: extraction is ALWAYS `Assurance::Unverified`.
  Missing issuer/expiration and wrong types are classified errors, not defaults.
  NumericDate is integer seconds with checked nonnegative conversion to absolute
  microseconds; negative/overflow values cannot wrap into future validity.
- `Claim.value.write_attribute` / `attribute_len`: JSON-derived STRING
  conversion, including nested containers. String values use JSON-escaped inner
  text plus NUL, preserving the C quote-stripping/data-length behavior. Other
  values use JSON text without NUL. Objects/arrays retain source insertion order
  and Jansson's usual comma/colon spaces. Integers/booleans/null/Unicode strings
  are fully handled. The explicit Jansson rendering profile uses17 significant
  digits for finite binary64 reals, %g fixed/scientific selection, normalized
  exponents, real-preserving .0 and uppercase hexadecimal control escapes.
  Rust core supplies correctly rounded decimal digits; fixed zeroizing scratch
  rearranges them without another rounding or allocation. Original credential/
  presentation bytes are never reformatted. Default generic JSON rendering is
  unchanged for other consumers.
- `presentation` returns the complete original JWT bytes (even if not parsed),
  matching the raw-copy source path, with original ID/type and checked field
  length. `check_binding` checks original ID/type/full bytes and still returns
  Unverified; it cannot turn a match into signature verification. PABC semantic
  inspection/presentation returns raw type2 with Unavailable. Unknown raw types
  return Unsupported. Failure preserves family, exact u32 type, stage and cause;
  no credential/JWT/claim content is embedded in errors or Debug.

Feature `attributes` reuses the existing `gnunet-identity/alloc` PURE text/table
feature boundary, without any identity SERVICE/runtime dependency. The added
`gnunet_identity::normalize_name_into(input,out,lowered,nfd,ordering)` itself
allocates NOTHING. `NameScratch` borrows/erases caller buffers and
`Claim::attribute(name_out,value_out,scratch)` constructs serialized-layer
STRING Attributes with exact Unicode18 lowercase/NFD names. Every failure erases
both entire output buffers and scratch; success borrows the final outputs. No Unicode table is copied. Default raw claim extraction stays noalloc and does
not assume ASCII normalization. This two-layer split preserves the current
workspace dependency/feature boundary.

The existing generic serde_json dependency does not expose bounded/zeroizing
private parser scratch or a default-noalloc tree. It is therefore not used to
materialize sensitive credential values: the shared gnunet-json foundation uses no heap and retains the complete needed
grammar. The credential Workspace is a thin domain wrapper; REST can use the
same parser without depending on credential semantics. No new registry/network dependency or production C FFI is introduced.

Intentional refusal differences from weak C code: strict valid base64url rather
than permissive/asserting malformed decoder behavior; complete JSON object/EOF;
no unescaped control or lone surrogate; duplicate-key Conflict; explicit capacity
failure; checked negative/overflow expiration rather than C signed/unsigned
wrap/undefined behavior. These are error contracts, not a reduced valid JSON
value-type subset. JWT header/signature are intentionally NOT made mandatory.

One aggregate
public_mock model source covers conversion, parse-only unsigned mock JWT,
issuer/expiration/address/structured claims, optional exact Unicode names,
full-payload original-ID presentation, raw PABC/unknown failure, malformed input,
capacity refusal and workspace erasure. There
was no key/crypto/store/native/model operation or private-file read/hash.

The active C JWT loader uses JSON_DECODE_ANY without JSON_ALLOW_NUL, so escaped
\u0000 is refused for both value and object-key strings in this profile. This is
separate from valid non-NUL control escapes such as\u001B, whose derived STRING
text is preserved. No parser NUL policy was changed by the formatter successor.

Normal rounding-to-nearest binary64/Jansson default
precision is the compatibility profile; process-global altered C rounding modes
are not imitated by this pure Rust API.

Remaining: an explicitly supplied
issuer/signature/audience/time trust policy (the active official JWT plugin
provides none); optional PABC cryptography/provider if later required; ticket
business/provider glue, persistence/source authority and production service;
C/native interoperability qualification. This is not all RECLAIM or a
verified-credential system.
