# REGEX automata and DHT artifacts

`gnunet-regex` compiles the GNUnet REGEX byte language and produces the state
and accepting blocks used by distributed search. The crate is `no_std` and
does not start a service or own a network, clock, or key store.

## Compile and match

Default builds compile entirely into caller-owned storage. `GraphMemory`,
`ProofMemory`, and `ArtifactMemory` provide temporary tables. `RecordMemory`
holds the completed records, edges, and text. The returned `AutomatonView`
borrows only the record memory, so the same `Compiler` can build another
automaton into a separate destination while the first remains in use.

```rust
use gnunet_regex::{ArtifactMemory, BuildError, Compiler, GraphMemory, Limits,
    ProofMemory, RecordMemory};

fn compile_example() -> Result<(), BuildError> {
    let mut graph = GraphMemory::<32, 48, 32, 16, 16, 32, 1>::new();
    let mut proof = ProofMemory::<256, 512, 64, 16, 2048>::new();
    let mut artifacts = ArtifactMemory::<16, 32, 64, 48>::new();
    let mut output = RecordMemory::<24, 64, 4096>::new();
    let mut compiler = Compiler::new(graph.workspace(), proof.workspace(), artifacts.workspace());
    let automaton = compiler.compile_into(b"(ab|cb)[x]", 0, Limits::default(), &mut output)?;
    assert_eq!(automaton.is_match(b"cb[x]"), Ok(true));
    assert_eq!(automaton.is_match(b"cbx"), Ok(false));
    Ok(())
}
```

The `alloc` feature adds `Automaton::compile` for owned, heap-backed results.
Both interfaces use the same compiler and expose the same borrowed record
format.

## Byte language

`(` and `)` group, `|` means union, and postfix `*`, `+`, and `?` modify
the preceding atom or group. Implicit concatenation binds more tightly than
union. Postfix operators may be chained, and an empty group within a valid
expression is ignored. Every other non-NUL byte is literal, including `.`,
`[`, `]`, backslash, and bytes above 127. Matching consumes the full input and
does not interpret Unicode or POSIX syntax.

An empty whole expression, dangling union, unmatched parenthesis, or postfix
without an atom reports a syntax offset. A nullable expression such as `a*`
can match an empty input. The slice API rejects embedded NUL; callers handling
C strings should pass the bytes before the first terminator.

## Capacity and failure

The compiler uses iterative Thompson construction, bounded subset
determinization, and partition refinement. Proof generation uses two dense
matrices and a shared expression DAG. That phase takes cubic work in the
minimized state count before serialization, so size both the matrix storage
and the work limit for the expected expressions.

`Limits` controls graph size, parser and traversal stacks, proof and label
bytes, synthetic entries, and charged work. The fixed storage capacities apply
independently of these logical limits. Large expressions can require many
distinct 24-byte lookup keys; an exhausted bound returns `BuildError::Limit`
instead of truncating the language or its entry set. Heap reservation and
arithmetic overflow have separate errors.

A fixed compilation invalidates the destination's previous view when it starts.
Failure leaves the destination without a visible automaton, even if some backing
bytes were written. Both the destination and the temporary workspace can be
reused. To preserve an existing live automaton during a replacement, compile
into a separate destination and switch only after success.

## DHT keys and blocks

`first_key` returns the number of raw input bytes consumed, capped at 24, and
their SHA-512 hash. `proof_key` hashes exact proof bytes without a terminator
or normalization. Proofs describe all strings from the start to the given state;
their spelling and the compressed graph may differ from the C compiler.
Destination keys always identify the proof bytes in the published block.

Publish the records from `states()` as well as the synthetic entries indexed
by `initial()`. Entries cover short accepting strings and 24-byte prefixes,
including cuts across longer edges. Compression `1` retains byte edges;
`0` follows linear paths to a boundary within the configured limits. Other
values cap the non-start edge length. The start state caps edges at 24 bytes.

`Record::encode` writes the official type 22 state body into a caller buffer.
The encoder checks the original integer widths, NUL constraints, and strict
block size limit below 62 KiB. The [accepting block API](src/accept.rs) uses the
accepting state's key for the type 23 DHT record and provides purpose 18 signing
material, encoding, and verification against an explicit key and time. DHT
submission, path verification, and signing authorization belong to the
[REGEX service adapter](../../adapters/regex-std/README.md).
