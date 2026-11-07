# GNUnet threshold mathematics

This new no_std crate implements fixed-v0.29.1 threshold arithmetic. It is
not the missing DKG/CONSENSUS/native service or complete SECRETSHARING support.

The default profile uses fixed stack storage and no heap/OS/ambient entropy. `alloc` adds owned polynomial, exponentiated coefficients, roster and actual
verified-partial vectors. Every Vec is fallibly admitted against its actual
capacity. Jobs that retain an existing input plus a new allocation check their
combined capacity. Fixed job storage, caller objects and simultaneous independent
jobs must also be included by their enclosing owner's aggregate admission; this
is not a measured process RSS bound or a global allocator quota.

`Group` uses the public header's exact1024-bit P/Q/G. `MembershipJob` performs
the order-q check. `Element` records a canonical residue without falsely
granting subgroup membership. Actual group public keys, c1, commitments and
partial decryptions have the checked `Subgroup` type; identity remains valid for
an aggregate secret/share of zero. `Scalar` and `Plaintext` own zeroizing secret
integers and have no Clone/Debug. Scalar imports require0<=s<q.

Plaintext import accepts any128-byte representative modulo p, including0 and
nonsubgroup residues. Ciphertext admission likewise reduces only for arithmetic:
its exact original256-byte c1||c2 remains fixed for equality, signature and
challenge scope. It requires a nonzero order-q c1 but does not impose a subgroup
restriction on c2. Local encryption emits the canonical C producer format. `PlaintextGenerate` handles arbitrary caller-bounded immutable signed magnitude
bytes and i64::MIN, reducing the exponent one byte per step. Actual encryption
uses rejection-sampled0<nonce<q and both exponentiations.

Shamir generation samples nonzero original coefficients, without substituting a
constant after entropy failure. Secret Horner evaluation and exponentiated
Horner evaluation both use original_index+1, including65536, not a shortened
roster offset or floating-point pow. Exponentiated coefficients and their exact
round1 presecret SHA512 commitment are available to a future DKG owner.

`AggregateJob` owns final-aggregation mathematics. A caller explicitly selects
`AggregateContribution` owners: peer, original index, subgroup coefficient vector
and the unique scalar for the local point. The original threshold stays
nonzero and bounded; each vector has that degree, and peers and indices are
unique. The local peer/index tuple either matches both columns or is absent. Each local scalar must match its original polynomial through `ShareCheck` before
it is added modulo q. Coefficients are multiplied once; the same aggregate
polynomial derives each selected row's sigma through original-index Horner.

`AggregateMaterial` preserves the original threshold, selected rows, aggregate
key, zeroizing scalar and optional local row position. It accepts fewer rows than
the threshold, an absent local row and an empty selection (zero scalar, identity
key). These are mathematical outcomes required to represent the standard DKG
end result; they do not imply usable threshold decryption. `Roster::check` retains
its stricter nonempty/threshold/uniqueness conditions and must be requested
explicitly by a consumer requiring a usable roster. An original polynomial index
is never used as a reduced row offset.

Requested and input/output Vec capacities, including spare input slots
and simultaneous coefficient owners, are checked before allocation. Work is
bounded across initialization, pair checks, scalar association and existing
arithmetic jobs. Each capacity is released with its owner. Failure,
invalid units or cancellation erase the partial sum and untaken result. This
layer infers no signature, source closure, FAIR knowledge/range proof or dealer
qualification from arithmetic; the host owns those protocol decisions. General
FAIR production and complete authenticated multi-participant780→783 remain open.

`FairProver` implements a checked original-domain construction attempt. It owns
the scalar and the Paillier encryption witness, samples the full
original2048-bit beta and a bounded unit randomizer, and computes the exact
public transcript equations. Only group exponentiation uses beta modq or modn;
the response remains the complete integer beta+e*x. A response wider than the
original128-byte field produces sticky `Source(TooLarge)`, erases the attempt,
and causes no truncation, modq substitution, share restriction or challenge retry. Thus this supplies construction code and representable transcript output,
not a generally usable FAIR profile or a knowledge/range certificate. The known
response-size obstruction remains open. Successful bounded construction uses
the same canonical wire encoder as the original parser. Entropy buffers,
randomizers, integer products, division quotients/remainders and powers are
zeroizing owners. No native signer, write receipt or DKG completion is inferred.

Owned `Evaluation::new_owned` uses the same original-index Horner algorithm as
borrowed evaluation. `take_owned_result` returns the unique polynomial and its
scalar so a reveal builder can evaluate the next original participant
without self-reference, secret clones or a second algorithm. Actual retained
input capacity follows that owner; failure/cancel immediately erases and
releases owned coefficients, while borrowed inputs remain with their caller.

`PartialProver` validates sigma=g^share, computes c1^share, samples beta, computes
both commitments and the exact original SHA512 challenge over bytes72..744. It constructs the response `(challenge*share+beta) modq`. A completed proof
can be signed by an explicitly supplied EdDSA key; alternatively
`UnsignedPartial` exposes only the original purpose23 region to a native
PILS signing owner, and verifies its returned signature under the same original
peer before producing complete872-byte output. No write/flag/timeout is a
signature. `PartialVerifier` verifies the original signature, ciphertext/peer
association, three group memberships and both DLEQ equations before it can
create `VerifiedPartial`.

`RosterCheck` verifies distinct original peers/indices and a usable nonzero
threshold incrementally. `CombineJob` accepts at least that many verified
partials, rechecks their exact original roster/sigma/cipher binding and uniqueness,
uses Lagrange coefficients at the original indices, and checks the interpolated
sigma product equals the original aggregate public key before returning the
Zp plaintext. Partial/empty quorum cannot be encoded as successful math. Native consensus conclusion, original request timeout and source cancellation
remain the enclosing protocol owner's separate gates.

Each advance has explicit1..64 work units. One unit is an exponent bit, scalar
draw, fixed-size multiply/add or original index/association comparison. Secret
power state uses a fixed-capacity two-product pattern per bit. Public Paillier
unit validation uses fixed-size2048/4096-bit GCD primitives. Cancellation/failure
erases job-owned coefficients, nonce, exponent, plaintext and power state; a
borrowed exponent/polynomial remains its caller's erasure responsibility. No
claim is made about compiler spills, caller copies or whole-system constant time.

The fixed C fair-encryption producer/consumer is actually active but internally
inconsistent. Its128-byte z stores `(r+e*x) modq`, while the Paillier equation
needs an integer response compatible with an unknown-order group; r is drawn
with2048 bits and e is a512-bit hash. The producer also multiplies g*r instead
of exponentiating, and its verifier has a wrong-width read, overwritten temporary
and reversed equality checks. These bugs are not copied. `FairEquationCheck`
checks the exact original c516||h128||t1_128||t2_512 transcript, unit/membership
conditions and two equations, but returns only `FairEquationResult`. It is deliberately not named or usable as `VerifiedFairProof`: no general fair
proof producer, zero-knowledge/range/security theorem or full DKG is implemented. No challenge shortening, extra field or private wire is introduced to conceal
that unfinished requirement. See the source review and primary-paper references.

Next layers still require an established interoperable fair-proof construction,
original roster/round qualification, DKG consensus, authenticated native lifecycle,
IPC/client ownership, original deadlines and source cleanup. The C
share-size overflow, missing threshold, reduced-roster index mistakes and unchecked
partial quorum are not reproduced as memory bugs or fabricated successes.

The no-allocation VerifiedPartial exposes its
original ciphertext and share commitment without permitting construction or
retargeting.

`FairRecoveryJob` implements the separate receiver-side bounded-rational
mathematics from Fouque--Stern section3.2. It adopts the original Paillier
plaintext and exact modulus, finds a/b with0<=a<2^1024 and0<|b|<2^512, checks
the original congruence, and recovers the scalar a/b modulo q. The fixed
2047/2048-bit modulus profile has n>2*A*B, ensuring uniqueness in these bounds. Extended Euclid stops updating at the first remainder below A, but executes
all2048 constant-time fixed-width division turns with masked state updates;
a fixed1024-bit modular inverse follows. The two-turn remainder-halving bound
covers every admitted input, without exposing a secret-dependent round count. There is no heap or entropy. All owned plaintext, coefficient, inverse and
untaken scalar work is zeroizing. The result is only a mathematical scalar:
callers must still verify the proof, signed source and g^share commitment. The Round2 owner uses the job before its unchanged ShareCheck. This does not
repair the general FAIR producer's response-size conflict or qualify full DKG.
