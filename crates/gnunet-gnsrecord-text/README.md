# Shared official record text

Allocation-free conversion for all35 value formats in the four active GNUnet
v0.29.1 GNS-record plugins at commit
`346358e26d4dcc2dc4f51bef5d52dca29c7d8165`:

- DNS: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, CERT, URI, TLSA, SMIMEA, CAA.
- GNS: PKEY, EDKEY, NICK, LEHO, VPN, GNS2DNS, BOX, SBOX, REDIRECT, `✞`.
- RECLAIM: ATTRIBUTE, ATTRIBUTE_REF, CREDENTIAL, PRESENTATION, OIDC_CLIENT,
  OIDC_REDIRECT and TICKET under their actual `RECLAIM_` names.
- MESSENGER: ROOM_ENTRY, ROOM_DETAILS, ROOM_EPOCH_KEY and ENCRYPTION_KEY under
  their actual `MESSENGER_` names.

`type_name` / `typename_to_number` also implement official ANY0 name lookup;
ANY has no record-value conversion. A registered number does not imply an
active plugin. The installed ABD command additionally requires the DEL
and ATTR grammar from its public library/contrib text source. Those two formats
are supported without claiming that the unbuilt C ABD plugin is installed. Unbuilt conversation formats, DID/FAEST and other unhandled registry entries
remain explicitly unsupported rather than receiving invented text.

`Codec::new(idna, Workspace::new(stage, names, work), profile, limits)` takes an
explicit complete `gnunet_dns::Idna` provider and a Messenger producer `Profile`. Call `string_to_value(kind, text, output)` or `value_to_string(kind, data, output)`;
both return the complete result length. `with_abd_layout(AbdLayout { align64 })`
selects the known original ATTR C alignment4/8; its default is the current target. No incoming data triggers layout guessing. Text contains no added NUL. The caller
owns final output and should treat private record/capability text accordingly. The codec exposes no payload Debug, key-file access or trust assertion.

The stage slice holds the whole result. Name arena510 and text work1024 cover
native DNS SOA and Unicode projection; callers may supply less and receive a
capacity error. Default input/output ceilings262140 cover maximum16-bit record
payload expansion, including hex and nested wrappers, without allocating those
buffers automatically. Every supplied byte of scratch is zeroized on
initialization, success, failure and Drop. Final output is changed only after
complete conversion and UTF-8 validation. The owning IDNA provider retains its
own explicit independent caller workspace/profile.

DNS names reuse the existing DNS reader/builder and complete IDNA backend;
Unicode tables are not copied. BOX/SBOX conversion is iterative with a finite
nesting bound. Existing parsing advances through original text once; ATTR uses
two bounded passes to preflight conjunction count/extent before encoding. Formatting traverses original record bytes, apart from bounded DNS/IDNA work. Generic
Base32GNS lives in `gnunet-gnsrecord` and is reused by typed zone identifiers and
all relevant record families. There is no heap JSON/value tree or plugin loader.

External formats and differences are explicit:

- TXT/NICK/LEHO/REDIRECT and RECLAIM string values are raw UTF-8 record bytes,
  without DNS character-string length prefixes or an extra terminator. Formatting
  stops at the first NUL like the reference `strndup`; arbitrary binary tails
  after NUL are not claimed to round-trip through these string schemas.
- GNS2DNS stores two terminated strings, split at the first `@`. VPN stores the
 32-byte peer, BE16 protocol, then terminated service name. Delegations use the
  complete typed58-character public key text and32-byte record value.
- Actual GNUnet SOA text orders RNAME before MNAME; binary DNS remains standard
  MNAME/RNAME. CERT uses standard padded base64; TLSA/SMIMEA use the existing
  native hex parser and lower-case hex output.
- Messenger text reverses packed field order exactly as the plugin does and
  encodes scalar bytes in Base32GNS. The explicit producer profile checks
  packed encrypted-length bounds; no hash, MAC, signature or decryption occurs.
- No C undefined memory behavior is replicated. Bounded parsing fixes CAA tag
  overflow/OOB reads, unallocated RECLAIM base32 destination, and CERT's accidental
  reassignment of certificate type while parsing the algorithm. Valid typed
  record wire remains standard. Bad numeric overflow/trailing fields are rejected
  instead of silently wrapping or using unchecked offsets. Exact C acceptance
  of malformed text is not an interoperability requirement.

The pure aggregate model checks independently specified wire values for every
active family, packed field order, Unicode conversion, maximum-length
hex expansion, nesting/capacity refusal and complete scratch erasure. It uses
only fixed public mock data. No crypto, key generation/derivation, private
key fixture/file, storage, native socket, C actor or node executes. This library
does not by itself complete REST, NAMESTORE applications or GNUnet services.

`recordline` provides the allocation-free active NAMESTORE line grammar, separate
from OS IO and authority lookup. `parse` returns a borrowed empty line, header or
record metadata/value. `format_header` and `format_record` write into bounded
caller output. Headers use the first dot in `<label>.<owner>:`; record values use
`TYPE EXPIRATION [pSrsC] VALUE`, with raw absolute/relative microseconds. `p`
clears PRIVATE, `S` sets SUPPLEMENTAL, `r` sets RELATIVE_EXPIRATION, lowercase
`s` sets SHADOW, and `C` sets CRITICAL. The lowercase SHADOW spelling follows the
fixed C reader; its exporter incorrectly prints S for both supplemental/shadow. No flag extension, private wire format or comment/escape syntax is introduced.

Maintenance/unknown flags, embedded CR/LF/NUL and headers that would change the
selected label are refused on formatting. Debug redacts record values. The caller
owns complete input/output bounds, CR/LF framing, record text conversion,
nonempty group replacement and IDENTITY selection. A header alone is not a
delete request; every explicit header is a new group, even if repeated. The
ordinary `namestore import-recordline`/`export-recordline` CLI connects this
shared grammar and the existing value Codec to the original production clients.

ABD DEL is the actual `ISSUER.ROLE -> SUBJECT[.ROLE] | BASE64_SIGNATURE | UTC_US`
text. The typed36-byte keys use existing Base32GNS, the complete68-byte typed
signature uses the existing shared text Base64 helper, and the expiration stays
an unsigned absolute microsecond value. Canonical singular DEL encoding restores
both signed terminators and purpose28; signed original case/Unicode/subject role
are never normalized or silently removed. Parsing/formatting authenticates no
signature, expiry, GNS source or delegation. The ABD core does that work. ATTR is the comma-separated conjunction of `KEY` or `KEY ROLE` entries. Terms
retain original order and linked role bytes. An empty conjunction, empty role,
non-UTF8 or a field requiring an escape grammar fails explicitly; binary codecs
remain separate. Two nonsecret source cases cover exact signed-field preservation,
internal bars/Unicode and explicit4/8 layout/term order. No ABD/native/interoperability credit.

Conditional CONVERSATION PHONE uses the version1/reserved0 104-byte value
and `PORT_BASE32-PEER_BASE32` grammar (103 and52 characters). The same caller-owned
zeroizing staging and final output commit apply; parsing establishes no GNS TTL,
peer identity, ringing signature or call authority. Unsupported versions and
nonzero reserved fields fail formatting because this grammar cannot retain them. Its C plugin is built only when the Conversation audio backend is selected.
