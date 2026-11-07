# Pure REGEX automata and official state artifacts

`gnunet-regex` is an independent pure Rust implementation of the pinned GNUnet
v0.29.1 REGEX byte language and the calculation/encoding needed by a future REGEX
service. It has no native, DHT, clock, key storage, service or background port. No production GNUnet FFI or new registry version is introduced.

Default features allocate nothing: `first_key`, `proof_key`, borrowed `BlockEdge`
and `EdgeSource`, `state_block_len` and `encode_state` operate on caller bytes. The explicit `alloc` feature enables `Automaton::compile(expression, compression,
Limits)`. A successful result contains the complete automaton, per-state proofs,
compressed transitions and complete synthetic entry records. Every allocation
uses fallible reservation; failed syntax/limits/allocation drop the unpublished
partial construction. This is an alloc compiler with explicit finite bounds,
not a claim of caller-buffer noalloc compilation.

## official language

Only `(`, `)`, `|`, `*`, `+`, `?` are operators. Implicit concatenation binds more
tightly than union; postfix operators affect the preceding atom/group and may
be chained. Group nesting and the empty-group behavior (`a()b` means `ab`) follow
the pinned parser. Every other non-NUL byte is literal, including `.`, `[`, `]`,
`{`, `}`, backslash, `^`, `$`, `-`, `:`, and bytes above127. No Unicode/UTF-8,
POSIX wildcard, range, escape, backreference, anchor or bounded-repeat syntax is
invented. Full-string matching consumes all input. Explicit slices containing NUL
are rejected, so there is no hidden C strlen truncation.

An empty whole expression, only-empty groups, dangling/leading union, missing
parentheses or a postfix without an atom return the original Syntax offset. The C parser has unsigned-underflow/assertion paths for several of these inputs;
those are rejected explicitly instead of executing undefined behavior. Empty
strings are matched correctly by nullable valid expressions such as `a*`.

The `ALLOWED_LITERALS` macro in the official header is a random-test alphabet,
not a parser whitelist. `regex.c` creates policy expressions from the same
operators and literal address/port strings; policy parsing belongs in the
separate pure VPN policy layer, not this automaton compiler.

## Construction and bounds

The iterative Thompson parser creates an epsilon NFA. Subset construction uses
bounded bitsets and explicit epsilon work stacks, not recursive DFS. Sparse
byte-sorted DFA transitions undergo deterministic partition refinement. Complete
start-to-state languages use the Kleene matrix recurrence and a shared expression
DAG. Expression text is expanded by a bounded iterative stack; neither the host
call stack nor implicit exponentially expanding strings are used as work memory. DFA subset explosion and inherently large proofs/entry sets are refused with a
specific BuildError::Limit. Limits never silently truncate language or artifact
sets. Checked arithmetic overflow and allocation refusal remain separate errors.

Independent limits cover original expression bytes, parser/traversal stack, NFA
nodes/edges, DFA nodes, aggregate subset words, transitions, matrix cells, proof
DAG nodes, individual/total proof bytes, compressed label bytes, initial records,
initial proof/edge metadata/label bytes, and charged work. Hash/copy work is also
bounded by the corresponding byte limits. These are explicit logical resource
bounds; Vec capacity growth and allocator overhead are not described as exact RSS. The proof algorithm is cubic in admitted minimized state count before expression
serialization; finite matrix/work limits are part of the public contract.

`compression=1` preserves byte edges. Otherwise paths compress through states
until acceptance, a join/cycle boundary, or the selected length cap. Start-state
edges cap at24 bytes as the official iterator requires; other edges use the
requested maximum, with0 meaning maximal paths within resource bounds. All
minimized rows/proofs remain available even when an incoming path skips an
intermediate row. This avoids deleting a target needed by a synthetic entry. Matching uses immutable internal target indices and does not allocate or hash
state names per input byte.

## Keys, proofs, entries and blocks

`first_key` hashes exactly the first min(input length,24) raw bytes with SHA-512
and returns the byte count consumed. `proof_key` hashes exact proof bytes with
no final NUL or normalization. Per-state proofs describe the language of strings
from the start state to that state. This implementation chooses independent
language-equivalent proof spelling; it does not claim byte-identical C canonical
expressions, state numbering, transition order or compressed graph shape. Destination keys are always the hashes of the retained destination proofs. The official regex block checker hashes proof bytes and checks literal edge
prefixes; it does not parse/canonicalize a C Kleene expression to derive the key.

Publish the `State::record()` records plus every `Automaton::initial(i)` record. Synthetic entries use literal consumed prefixes, accepting prefixes below24,
24-byte cuts across a longer compressed edge, and the official short terminal
string bridge. Duplicate synthetic prefixes coalesce their deterministic edges. A regular state whose proof is already the exact literal prefix supplies that
entry directly. Distinct proofs with equal SHA-512 are refused as Conflict. Additional valid hash(empty) entries cover nullable expressions, and legal
literal-dot paths are included. The source iterator's dot skip and cur_len>0
empty-input omission contradict its literal parser/search key operation; those
internal defects are not defaults or compatibility switches here.

The default-noalloc state encoder writes exactly: BE16 proof length, accepting,
edge count, unique destination count; original-order unique64-byte destination
keys; BE16 destination-index/token-length pairs; raw proof; raw tokens. It checks
NUL/16-bit sizes and the official strict `<62*1024` total block bound before
writing. EdgeSource must obey its documented stable indexed-borrow contract. Compiler success preflights every generated record against this block limit. No state block, accepting flag or hash is a DHT submission or a signed provider
advertisement. Signing/announcement ownership are external service concerns.

## Evidence boundary

The sole `tests/automaton.rs` model combines grammar precedence/postfix/groups,
byte literals/high bytes, nullable matching, compression settings, independent
language-expression checking for finite noncyclic cases, existing
`gnunet-block` structural/key checks, destination closure, the VPN search shape,
synthetic entry walks including dot/empty, and representative capacity errors.

This is complete callable pure core/artifact code within explicit limits. It is
not a REGEX service, automaton/DHT interoperability qualification, a native DHT
implementation, signed REGEX_ACCEPT producer, full node or whole-goal completion.

Central integration replaces linear synthetic-prefix deduplication with a
fallibly growing exact-byte hash index. It grows with admitted records at load
at most one half; collisions retain exact proof comparison and charged work. The wire key remains SHA-512. Broad cyclic languages can inherently require an
exponential number of initial24-byte lookup keys; explicit bounds reject those
complete announcements rather than publishing a truncated set. The focused
model tests that refusal and a fixed24-byte namespace followed by the same
branching grammar, plus one long non-start compressed-edge boundary case.
