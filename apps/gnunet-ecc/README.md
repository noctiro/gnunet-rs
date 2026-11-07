# Ordinary gnunet-ecc

This MPL-2.0 app implements the installed GNUnet offline peer-key utility using
existing Rust cryptographic and PROGRAM ports. It does not contact IDENTITY,
PILS, a resolver or any network service. Files are exactly consecutive raw
32-byte Ed25519 seeds; there is no typed36 wrapper, Rust header or side database. Only an explicit filename is opened. No user key directory is searched.

`-p/--print-public-key FILE` prints each corresponding public identity as one
canonical52-character Base32GNS line. `-x/--print-hex FILE` prints lowercase hex
with the current C prefix `HEX:: `. Explicit `-P/--print-private-key FILE`
prints the original private raw seed as Base32GNS. `-i/--iterate [-e/--end COUNT]
FILE` writes zero-based public rows on stderr, with the C minimum-width4 index;
COUNT defaults to UINT32_MAX. File content is streamed one32-byte zeroizing row
at a time. Empty/nonregular/symlink inputs, incomplete records and observed
source changes fail instead of silently succeeding or discarding a tail. An
explicit zero iteration limit validates the file and emits no rows.

`-g/--generate-keys COUNT FILE [VANITY_PREFIX]` obtains OS entropy and
streams matching seeds into one exclusive0600 sibling file. COUNT is the full
C uint32 range, not a small fixture count. The optional prefix is a public-bit
prefix, accepting the common GNUnet Base32 case and O/I/L/U aliases. Its length
is0..52: compare min(5*length,256) public bits. At length52, the low four
unused padding bits are ignored as in the shared Base32 decoder; re-encoding
is canonical0/G in the final symbol. The original C out-of-bounds33rd-byte
comparison is not reproduced. A full legal52-symbol prefix remains a valid,
possibly impractical search. No new private matching algorithm is substituted.

Generation explicitly supports an absent target or an existing empty/raw32
regular target. A symlink, other file type or partial old record is refused. The old target is not truncated while entropy/vanity work runs. After complete
staging and file sync, the original observed target metadata is checked
again. An existing selected regular path is atomically renamed over; an initially
absent path uses a kernel no-clobber hard link. The sibling is then removed and
the original directory is synced through a checked same-directory descriptor. The metadata check detects observed changes; it is not an inter-process CAS,
lock or guarantee against adversarial same-UID races. Unsupported filesystem
operations return their error without a non-atomic fallback.

publication is recorded before any post-operation guard or directory-sync
error. A late stop/error therefore may report a complete published target, with
an independent missing durability confirmation; it never pretends to roll back
that native effect. Before the publish syscall, cancellation/failure cleans only
the original private sibling and preserves the old selected target. A publication
error retains its native errno, grants no rollback/no-effect proof and is
never blindly retried. The published flag records only native confirmation. Normal cleanup
is attempted once independently of failed time/cancel guards. An unconfirmed
sibling path and the cleanup error are retained in failure diagnostics;
a replaced path/inode is not deleted instead. Unexpected future abandonment
uses the same original-inode best-effort cleanup. No secure-erasure or kernel
cache guarantee is claimed.

`-E/--examples` prints two fresh ECDHE key pairs, their raw private/public
Base32 and hex, then the legacy SHA512(X25519) shared value. It uses
`EcdheSecret::from_bytes/public_key/exchange_hashed` and never an Ed25519-to-DH
or HPKE private conversion. As in current C, E takes precedence without opening
a positional file. Remaining operation precedence is i, g when COUNT>0, then
x, p, P. There is no implicit create/read with no selected operation. Other
operations reject unused positional arguments. `--end` is the ordinary long
spelling; the C descriptor's accidental `end=` name is not copied. The old man
page's implicit creation and PKEY wording do not describe the current handler's
read-only raw-Ed25519 print path.

Only explicit P or E writes private material. Original seed, DH material and
encoded private output scratch are zeroized on success and every error. Secret
owners have no Debug/Clone/export wrapper added. Diagnostics retain only actual
counts, native causes and public paths, never key bytes or private output lines. Partial stdout/stderr writes remain counted and cause failure if unfinished;
only writes/flushes establish local output. Such writes prove no external
reader processing or key-file durability beyond the native sync observations.

Standard PROGRAM c/L/l/help/version/default configuration and Clock are reused. The first-exec shared startup port captures the original parent-control owner;
this utility has no listener and retires offered activation descriptors instead
of treating them as input. SIGINT/SIGTERM and corresponding parent bytes
stop the original operation. Parent EOF closes only that control registration. No extra task/thread/provider worker is spawned. Every configured WORK_UNITS
(default32,1..65536) bounded rows/candidates yields the caller's Tokio driver so
signals/timers can run. Control is checked around IO and crypto work.

Optional `--timeout DURATION` or `[ecc-rust] TOTAL_TIMEOUT` supplies one original
canonical/native operation target; zero selects configuration, whose default0
means no time limit. `--max-attempts COUNT` or `MAX_ATTEMPTS` supplies an optional
total entropy-candidate bound (default0 means none). Limits never renew on a key,
vanity retry, IO progress or shorter wait. A finite native target is captured
before its canonical provider sample. A logical rollback/clock/logging failure
stops work. The same final guard runs after independent cleanup. Filesystem,
entropy, group primitives and synchronous stdout/stderr calls are finite native
calls, not OS-preemptible operations; a signal cannot retroactively prevent an
already executing syscall. There is no arbitrary input-file or total-key memory
aggregation limit: streaming memory remains constant, while caller-selected
operation bounds/cancellation remain authoritative.


Primary functional source: fixed GNUnet346358e26d4dcc2dc4f51bef5d52dca29c7d8165,
`src/cli/util/{meson.build,gnunet-ecc.c}`, `src/lib/util/{crypto_ecc.c,strings.c}`,
and the installed `doc/man/gnunet-ecc.1`; current C producer behavior takes
precedence over stale man text. This implementation/template organization is
independently written, without copying the GNU implementation.
