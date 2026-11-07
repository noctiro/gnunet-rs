# Rust HPKE API and official operation mapping

`hpke::{Mode,Kem,Role,Parameters,Context,OneshotLengths}` are new. Parameters
contains borrowed kem/mode/info/psk/psk_id fields. It intentionally has no Debug
implementation because it borrows a PSK. `Parameters::base(info)` chooses only
the official default0020 Base mode; `base_elligator(info)` selects0022 for its
distinct typed setup operations. Context is an exclusive erased owner.

The exact new public operation signatures are in `src/hpke.rs`:

* sender_setup2(&EcdheSecret, Option<&EcdheSecret>, EcdhePublic, &Parameters)
  -> Result<(EcdhePublic,Context),Error>;
* sender_setup(EcdhePublic, info, &mut impl Entropy)
  -> Result<(EcdhePublic,Context),Error>;
* receiver_setup2(EcdhePublic, &EcdheSecret, Option<EcdhePublic>, &Parameters)
  -> Result<Context,Error>;
* receiver_setup(EcdhePublic, &EcdheSecret, info) -> Result<Context,Error>;
* sender_setup2_elligator(&elligator::Secret, tweak, EcdhePublic, &Parameters)
  -> Result<(elligator::Representative,Context),Error>;
* sender_setup2_elligator_random(EcdhePublic, &Parameters, &mut impl Entropy,
  NonZeroUsize) -> Result<(elligator::Representative,Context),Error>;
* receiver_setup2_elligator(elligator::Representative, &EcdheSecret, &Parameters)
  -> Result<Context,Error>;
* Context::seal(aad, plaintext, out) -> Result<usize,Error>;
* Context::open(aad, ciphertext_with_tag, out) -> Result<usize,Error>;
* Context::seal_in_place(aad, bytes_with_tag_capacity, plaintext_len)
  -> Result<usize,Error>;
* Context::open_in_place(aad, bytes, ciphertext_len) -> Result<usize,Error>;
* seal_oneshot(recipient,info,aad,plaintext,out,&mut impl Entropy)
  -> Result<OneshotLengths,Error>;
* seal_oneshot_with_ephemeral(recipient,&ephemeral,info,aad,plaintext,out)
  -> Result<OneshotLengths,Error>, the deterministic setup2+seal composition;
* open_oneshot(&recipient,info,aad,ciphertext,out) -> Result<usize,Error>.

Context getters are role(), sequence(), sequence_be(), nonce() and
exporter_secret()->&Prk. The last returns a scoped opaque borrow, without
inventing an absent upstream RFC Export function. Helpers seal_length and
open_length check caller-buffer arithmetic. OneshotLengths reports
`total_written=32+plaintext_len+16` and the observed C return
`c_reported_ciphertext_len=plaintext_len+16` independently.

Existing EcdheSecret gains hpke_encoded_length()->36,
encode_hpke_private(&mut[u8])->Result<usize,Error>,
decode_hpke_private(&[u8])->Result<(Self,usize),Error>, and clear(self).
Explicit encoded output is caller-owned secret material and must be erased by
its owner. Import does not clamp arbitrary serialized bytes, matching C read;
DH itself clamps and deterministic key creation already serializes the official
clamp. EcdhePublic gains hpke_encoded_length()->36; its existing public codec
already emits BE32 type0 + raw32 and leaves caller tail capacity untouched.

The28 public source-function inventory maps context8 to the new operations,
private/public codec and key lifecycle10 to these/new/existing scalar methods,
standard KEM3 and EdDSA KEM2 to the existing KEM/typed-conversion compositions,
identity conversions2 to the existing raw-PKEY / EdDSA-seed / Edwards conversion
operations, and Elligator KEM3 to the existing typed `elligator` module. The
Elligator context setups reuse that module and GNUnet's fixed HPKE0020 schedule;
ordinary setup remains0020-only. Typed Rust operation
composition is not a promise of C union ABI or generic untyped key imports.

Error categories: Unsupported for undeclared/unimplemented selectors or Auth
modes; InvalidInput for inconsistent PSK rules or wrong role; Capacity for
caller storage; Truncated for missing enc/tag; Authentication for invalid DH or
tag; TooLarge for exhausted message sequence or payload limit; Overflow for
checked lengths; Entropy for explicit entropy failure. C exposes only its
GenericReturnValue for these functions, so normal-C comparisons bind success/
failure, valid bytes and state, not fictitious equality of richer Rust variants.

No API admits rollback, clones a secret Context or leaks a borrow beyond it.
This safe Rust surface intentionally restricts arbitrary public C-struct mutation;
these ownership decompositions are explicit and separate from valid-operation
interoperability. There is no allocator, OS DNS/network or global random source
in any new production operation.
