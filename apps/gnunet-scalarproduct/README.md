# Normal SCALARPRODUCT command

`gnunet-scalarproduct -e 'name1,3;name2,-7;' -k shared-session [-p PEERID]`
uses ordinary GNUnet PROGRAM options, selected configuration/logger and an
explicitly driven Resolver with one shared clock. `-p` selects requester/alice;
without it the command is responder/bob. The role configuration section
is `scalarproduct-alice` or `scalarproduct-bob`; it selects the endpoint
and its ECC/Paillier service implementation. No service or helper is spawned.

Key labels and the nonempty transaction identifier are hashed from their exact
argument bytes as the official CLI does. Vector syntax has semicolon-terminated
key,signed-i64 records; the last comma splits each key from its value. One
optional pair of literal outer single quotes is accepted. Malformed tails,
empty keys/values, over-budget input and duplicate hashed keys are refused. Peer identities use the existing GNUnet public-data decoder.

Requester success prints one signed uppercase hexadecimal integer and newline. The original service payload is MPI STD, a signed big-endian value. The command
scans it as signed, adds it when the independent range word is positive and
negates it otherwise, matching the C API operation. Empty MPI is zero. Leading sign padding is not discarded as an unsigned-magnitude convention. No metadata header is added to stdout. A responder success is a status
observation logged through the selected logger; it prints no fabricated product. Unknown/failure/disconnected status words remain non-success with original
response fields and input receipts retained in the failure.

The native owner closes before a result is exposed. Native source loss and
signals physically cancel the same original computation; they do not synthesize
a scalarproduct reply. Whole/partial input facts remain distinct. Stdout uses
one retained bounded result, partial-write cursor and final flush, with
an independent output target clamped to the original total budget. A synchronous
stdio call cannot be preempted: a late return is classified as failure even if
bytes escaped. Inherited descriptor flags are not modified. Source, output and
Resolver cleanup failures remain separate; selected logging is not bypassed
through an extra fd2 fallback after it owns diagnostics.

`[scalarproduct-client-rust]` provides MAX_FRAME_BYTES, MAX_ELEMENTS,
VECTOR_BYTES, RESULT_BYTES, IO_SLICE_BYTES, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES,
INITIAL_TIMEOUT, WRITE_TIMEOUT, INPUT_TIMEOUT, TOTAL_TIMEOUT and OUTPUT_TIMEOUT. Defaults are65535-byte frames,65536elements,16MiB vector-plus-index storage,
65519result bytes,4MiB argument vector,256KiB stdout,30s initial/write,15s partial
input,600s total and10s output. Actual retained vector/frame/output capacities
are checked, with no claim of measured RSS. `num-bigint=0.4.8` is already in the
parent lock and is used only for correct signed integer interpretation/display.

It supplies
a native caller and CLI, not Rust scalarproduct computation/crypto services,
peer reconciliation, a full owner or whole-GNUnet completion verdict.
