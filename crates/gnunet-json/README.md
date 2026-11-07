# Bounded noalloc JSON foundation

Shared parser/value/erasure code extracted from the completed RECLAIM
credential helper, reusable by REST without a credential/service dependency. Default no_std/noalloc; only existing gnunet-types and zeroize dependencies.

`Workspace::new(payload,tokens,nesting)` owns exclusive caller buffers. `parse`, `parse_with` and `parse_with_check` validate complete JSON and expose a
borrowed Document only after finite byte/token/depth/work and semantic admission. The decoder/fill runs once. Its returned length is checked. The higher-ranked
semantic check cannot return a borrowed Document; any fill/parse/check failure
clears the SAME original buffers. Workspace initialization, explicit clear and
Drop erase every byte and each Token/Nest numeric field via Zeroize. Live
Document/Value/string views prevent safe-Rust reuse/drop. There is no heap,
worker, native/crypto/key operation or recursively allocated generic Value tree.

Parser supports every JSON value category and complete nested structures,
UTF-8, escapes/surrogate pairs, signed i64 integers and finite f64 reals. Explicit
nesting max64 bounds iterative parser storage and formatter recursion. Duplicate
decoded keys return Conflict, trailing input/malformed/lone-surrogate/NUL strings
are refused, unrepresentable numbers Overflow, exhausted caller resource Capacity. No partial document or empty-success fallback is returned. Whitespace charges
one work unit per byte. Key comparison
work is also charged; original byte bounds cover the initial UTF-8 pass.

Document.root returns Value; Value exposes original JSON, decoded string,
integer, boolean, object get/members and array elements. Views allocate nothing,
retain insertion order and have redacted Debug. Root can be any JSON type. `Value::{encoded_len,encode}`, JsonString escaped/quoted encoding and free
`string_len/write_string` write into caller buffers after full preflight. Object/array rendering uses standard spaced separators. Default rendering keeps
shortest round-trip finite f64 text and lowercase hexadecimal control escapes. Explicit `Format::Jansson` on `Value::{encoded_len_with,encode_with}` and
`JsonString::{encoded_len_with,encode_with}` selects default17-significant-digit
text and uppercase hexadecimal control escapes throughout nested values. It uses the rounded scientific exponent for %g notation selection, removes
unneeded fraction zeros and exponent plus/leading zeros, and appends .0 when
needed to preserve type. One32-byte plus one17-byte zeroizing scratch owner
holds decimal digits, with no heap, libc, locale or new dependency. The original
borrowed JSON and generic default rendering remain unchanged.

Credential public API and selection logic remain unchanged. Its thin wrapper
still chooses the original JWT payload, returns Unverified, applies its own
claim cap BEFORE a document escapes, and uses credential-specific STRING
quote-stripping/zero semantics outside this generic layer. Credential tests cover the public mock model and whitespace work accounting.

This does not add REST
handlers or an HTTP listener by itself; those continue in a separate candidate.
