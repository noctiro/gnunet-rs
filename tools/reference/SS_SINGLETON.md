# Normal singleton SecretSharing public-API caller

`ss_singleton_client.c` links the unchanged official SecretSharing and util
libraries. It uses `GNUNET_PROGRAM_run` configuration and starts no service.
After a separately supervised normal Rust PILS and SECRETSHARING service are
ready, invoke its compiled binary with:

```
/ABS/ss_singleton_client -c /ABS/node.conf -L ERROR LOCAL_PID52 START_US DEADLINE_US
```

`LOCAL_PID52` is the current PILS public identity. Both absolute times are
decimal GNUnet microseconds; start must precede deadline and the deadline must
be at most60 seconds ahead. Both requests retain these same original values.
One native60-second elapsed-time alarm starts before PROGRAM preparation and
is never renewed. The caller checks both clocks at each business boundary and
uses the scheduler's normal SIGTERM cleanup path on native expiry. An external
supervisor must still enforce its original native process bound and consume the
exit, including during an uninterruptible synchronous library call.

The caller requests singleton780 with an empty peer list and threshold1. Its
actual783 callback must supply a Share whose public serialization has426 bytes,
threshold/count1, local/original index0, the expected peer and matching public
key. The temporary serialization remains private in memory and is erased. The
pinned official API supplies an incorrect `ready_peers` pointer; the caller
checks the roster through public `share_write`, without patching that API
or reading an internal C struct.

The original callback Share is retained. The public plaintext-generation API
creates a nontrivial full128-byte group element; public encryption produces its
ciphertext. A new official781 uses that exact Share and ciphertext, and its
actual782 callback must match all128 plaintext bytes. Only bounded public events
and the public peer identity are printed. Share/secret bytes are never logged,
hashed or written to disk. Public API callbacks own automatic handle retirement;
the caller clears those handles and defers its next phase/stop until callbacks
return. Cleanup cancels still-owned original handles/tasks and destroys the Share.

Success requires exactly one `OPEN`, `GENERATED`, `ENCRYPTED`, `DECRYPTED` and
`END passed=yes generated=yes encrypted=yes decrypted=yes reason=complete`, plus
the original exit0. Partial progress, timeout, API failure, external stop
or an output failure is not a pass. This is a C public-API component, not a C
peer algorithm, multiparty DKG or FAIR qualification. Writing this source does
not supply a build or runtime receipt.
