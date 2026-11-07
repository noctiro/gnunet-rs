# GNUnet Paillier primitive

This independent `no_std` crate implements the arithmetic used by the
installed old SCALARPRODUCT Paillier profile. It has no allocator, RNG singleton,
network/file operation, native dependency, C FFI or hidden task. It uses existing
RustCrypto crypto-bigint0.7.9 with zeroize, the existing explicit fallible
`gnunet_crypto::Entropy` port and gnunet-types only; no new registry package or
download is needed.

The public key is an unsigned256-byte BE modulus. Ciphertext is exactly signed
BE32 `remaining_ops` followed by a512-byte BE integer (4096bits). Secret export is
lambda256BE || mu256BE in a zeroizing buffer; there is no unchecked secret import. Wire decoding alone grants no arithmetic/key/identity authorization. An admitted
remote modulus must be odd and have2047 or2048 bits; that shape does not prove
its factorization or trust. Math validates ciphertext unit/range under
that original key. Standard ciphertext bytes contain no key identifier or proof
of encryption origin; the session must bind the original public n/transcript,
not infer authorization merely because an integer is in the unit group.

`Keygen` draws real1024-bit odd candidates with their top2bits set, sieves small
factors, and performs80 independent uniformly sampled strong Miller-Rabin tests
per accepted factor. Factors must differ. At most2^20 total candidate draws gives
an unconditional union bound at most2^-140 on any composite passing all tests,
assuming the explicit entropy port is independent/uniform/cryptographic. These
are strong probable primes, not mathematical certificates. This assurance is not
a claim of128-bit security for the2048-bit Paillier cryptosystem itself. No odd
number is accepted merely because it has the right shape or passes one base. All repeated candidate/base/nonce rejections have finite budgets.

Generated n=p*q is genuinely2048-bit; lambda=(p-1)*(q-1), g=n+1 and
mu=lambda^-1 modn follow the official simplified key. Encryption samples a
uniform unit r in Zn*, rejecting zero and nonunits, and computes
(1+n*m)*r^n modn². Decryption computes exact L(c^lambda)*mu modn; nonexact L/range
is a failure. Homomorphic addition multiplies ciphertexts modn², requires
each original remaining counter in1..2047 and returns min(counter)-1. Zero
remaining is a successful last addition and refuses a subsequent one. The raw
signed count is preserved, not treated as any-nonzero success or authentication.

`PublicKey::encrypt_with_witness` explicitly requests a typed
`EncryptWithWitnessJob`. Its result owns the same unit randomizer that
formed its ciphertext and the original modulus. The result has no public
constructor, Clone or Debug; consuming it transfers the nonce only in zeroizing
storage. Ordinary `EncryptJob` immediately discards that nonce after setting up
its power and has no separate retained-nonce field. Both public jobs share one
private encryption engine, with identical sampling, counters, arithmetic and
bounded progress. Failure, partial/ready cancellation and drop erase the witness. This ownership interface supports the original FAIR response without recovering
already-erased coins or running a second independent encryption algorithm.

Remaining capacity follows the fixed C bit-length formula, with a finite m=0
case, clipped by caller desire and modulus safety. The extra true-modulus
cap matters for admitted2047-bit C products; normal2048-bit values retain the
official count. Plaintexts are owned Zn residues. Signed magnitude conversion
uses the residue; it does not enter C's negative-MPI counting loop. The
SCALARPRODUCT session layer must still use its official positive offsets, masks,
permutation, signed result/range and transcript rules; this primitive does not
pretend that those protocol operations are complete.

Keygen/EncryptJob/DecryptJob expose bounded `advance`, once-only `take_result`
and `cancel`. One unit advances one exponent bit, one sieve/strong-test cursor,
one random trial, or one fixed-size arithmetic boundary. Large bigint gcd,
parameter construction and final inversion/division remain finite fixed-size
primitives; calls are not preemptible inside those RustCrypto operations. No
clock, deadline renewal or IO success is fabricated. The containing protocol
continues to own its deadlines/epochs/resources and cancellation policy.

Jobs own the original mathematical key snapshot, preventing self-references or
later key rotation from rebinding in-flight work. Public Montgomery caches are
copied without allocation; private exponent and mu copies are zeroizing. There
is no public PrivateKey Clone/Debug/Display. Original message/nonces/candidates,
secret modular states, encodings and partial entropy buffers erase on failure,
cancellation and drop; unnecessary secret work is also erased on successful
completion. Original error survives later cancel/cleanup. This is owned-state
erasure, not a proof about compiler register/spill copies or side channels in
every dependency/platform. Prime search varies by random/primality work.

Their private test construction cannot
weaken the production modulus gate and gives no2048-bit keygen, C/native, RNG,
security, performance or interoperability credit. No crypto/model/test/parser/entropy/native/storage/network behavior
ran. Selected macOS/GNU Linux and thumbv6m no-system checks and the three
changed-graph architecture guards passed. The
Paillier SCALARPRODUCT session/peer algorithm and normal host profile remain
a separate required integration, alongside the default ECC profile.
