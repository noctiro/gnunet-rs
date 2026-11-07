# Normal Base32 bytes command

`gnunet-base32` encodes raw stdin to the canonical uppercase GNUnet Crockford
alphabet. `-d` / `--decode` decodes stdin to raw stdout. No newline, terminator,
key interpretation, filename operand, network service or helper process is added. Standard GETOPT help/version stop before acquiring stdin or a spool.

The command uses the existing `gnunet-gnsrecord` codec, including lowercase and
O/I/L/U aliases. It does not trim whitespace or accept `=`. Empty input succeeds
with empty output. Encoded lengths modulo8 must be0/2/4/5/7; the final symbol's
unused low bits are ignored as in the official codec. Invalid digits or trailing
lengths fail. The C utility's single-byte/zero-output-size accidental success is
not reproduced; a single invalid character or LF is rejected.

Encoding uses complete5-byte groups plus one final residual group. Decoding
uses complete8-character groups plus an independently validated final residual
group. Input/output arrays are fixed4104/6574 bytes, with at most7 carried input
bytes. There is no arbitrary total4KiB input limit or full-file RAM copy.

To preserve rejection before stdout, decoding writes only converted bytes
to a private disk spool until EOF and complete validation. The spool is
created only for the first nonempty decoded block; empty decode and invalid
zero-output tails do not depend on TMPDIR or create scratch files. One newly created
0700 directory contains a create-new0600 file. The original file/directory inode
and link facts are checked before the file is unlinked and the empty directory
removed. Both operations must actually succeed before decoding continues. The
remaining anonymous original File is the sole data owner; no path is reopened. After validation, it is rewound and copied to stdout in bounded chunks.

The spool grows with decoded input and the filesystem can refuse it. Disk space, filesystem latency, allocator/runtime overhead and measured RSS are
not promised by a fixed application buffer. Scratch is not a durable artifact;
no fsync, secure erase or observable File-drop close status is claimed. A failed
creation/cleanup retains the original error and any unconfirmed directory path;
it never authorizes deleting a replacement or silently becomes a successful run.

Stdio is safely duplicated and registered with the existing `RegisteredIo` for
pipes/terminals; regular files use bounded synchronous IO without a hidden
blocking worker. Unregisterable character devices such as `/dev/null` use actual
nonblocking IO with a10ms retry timer after WouldBlock. Both original stdio flag
snapshots precede either change. Deregistration precedes restoration and drop;
shared open-file descriptions and XNU's write-history flag use the normal
terminal's existing ownership rule. Independent flag changes are reported rather
than overwritten.

SIGINT/SIGTERM are checked at IO turns and cancel the original conversion. Actual
read, spool-write and stdout-write prefixes are retained before a later failure. Decode validation prevents malformed input from writing a prefix, but valid
output can still be partial on stdout error/cancellation: stdout is not an atomic
artifact or durability receipt. Native filesystem operations cannot be forcibly
preempted by cooperative cancellation. Abrupt SIGKILL cannot restore shared flags.

Exit statuses are0 success/help/version,1 options/setup,2 stdin,3 malformed
Base32,4 stdout,5 spool,6 cleanup-only failure, and128+signal for handled
cancellation. Failure diagnostics preserve the original typed cause, independent
stdio restoration/spool cleanup errors and byte/completion facts.

It adds this ordinary
utility only, without granting whole GNUnet or other utility qualification.
